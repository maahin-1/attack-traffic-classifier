"""Stream the pinned CIC-DDoS2019 archives into Experiment 006 features.

This adapter does not load models or choose thresholds. Invalid feature rows are
returned with a reason so callers can count them without silently dropping data.
"""
import csv
import hashlib
import io
import math
import zipfile
from pathlib import Path

from .prepare import FEATURES

ARCHIVES = {
    "calibration": ("CSV-01-12.zip", "d5224f73b59f2be783b620bc7046f4bf467c1fe226cfdbc036359ab40f32930d", "2018-12-01"),
    "assessment": ("CSV-03-11.zip", "a81d8ce59a819d13e6bfea4e4812d6d144d0572b6d2c42d8e0c0a8cf1c26c263", "2018-11-03"),
}
ALIASES = {
    "Total Fwd Packet": "Total Fwd Packets",
    "Total Bwd packets": "Total Backward Packets",
    "Total Length of Fwd Packet": "Total Length of Fwd Packets",
    "Total Length of Bwd Packet": "Total Length of Bwd Packets",
}
FAMILIES = {
    "BENIGN": "BENIGN", "UDP-lag": "UDP-Lag", "UDPLag": "UDP-Lag",
    "TFTP": "TFTP", "Syn": "SYN", "DrDoS_UDP": "UDP", "UDP": "UDP",
    "DrDoS_SSDP": "SSDP", "DrDoS_SNMP": "SNMP", "DrDoS_NTP": "NTP",
    "DrDoS_NetBIOS": "NetBIOS", "NetBIOS": "NetBIOS",
    "DrDoS_MSSQL": "MSSQL", "MSSQL": "MSSQL",
    "DrDoS_LDAP": "LDAP", "LDAP": "LDAP", "DrDoS_DNS": "DNS",
    "WebDDoS": "WebDDoS", "Portmap": "PortMap",
}


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def iter_csv_rows(archive, expected_date):
    """Yield records from a ZIP, retaining invalid rows with an explicit reason.

    Caller must verify the archive hash and protect assessment access separately.
    A structural error, unknown label or wrong capture date stops the run.
    """
    with zipfile.ZipFile(archive) as bundle:
        members = sorted((x for x in bundle.infolist() if not x.is_dir() and x.filename.lower().endswith(".csv")), key=lambda x: x.filename)
        if not members:
            raise ValueError("Archive contains no CSV members")
        for member in members:
            with bundle.open(member) as raw, io.TextIOWrapper(raw, encoding="utf-8-sig", newline="") as text:
                reader = csv.reader(text)
                headers = [name.strip() for name in next(reader)]
                if len(headers) != 88 or len(set(headers)) != 88:
                    raise ValueError(f"Unexpected header in {member.filename}")
                source_names = [ALIASES.get(name, name) for name in FEATURES]
                if len(set(source_names)) != len(source_names) or not set(source_names + ["Label", "Timestamp"]).issubset(headers):
                    raise ValueError(f"Missing or ambiguous features in {member.filename}")
                indices = [headers.index(name) for name in source_names]
                label_index, time_index = headers.index("Label"), headers.index("Timestamp")
                for number, row in enumerate(reader, 2):
                    identity = f"{member.filename}:{number}"
                    if len(row) != len(headers):
                        yield {"record_id": identity, "error": "column_count"}
                        continue
                    label = row[label_index].strip()
                    if label not in FAMILIES:
                        raise ValueError(f"Unknown label at {identity}: {label!r}")
                    if not row[time_index].strip().startswith(expected_date + " "):
                        raise ValueError(f"Unexpected capture date at {identity}")
                    record = {"record_id": identity, "source_label": label,
                              "family": FAMILIES[label], "label": int(label != "BENIGN")}
                    try:
                        values = [float(row[index]) for index in indices]
                    except ValueError:
                        record["error"] = "nonnumeric_feature"
                    else:
                        if not all(math.isfinite(value) for value in values):
                            record["error"] = "nonfinite_feature"
                        elif values[0] < 0:
                            record["error"] = "negative_duration"
                        else:
                            record["features"] = values
                    yield record


def iter_pinned_rows(data_dir, role):
    """Verify the chosen archive before streaming its records."""
    if role not in ARCHIVES:
        raise ValueError("Role must be calibration or assessment")
    filename, expected_hash, date = ARCHIVES[role]
    path = Path(data_dir) / filename
    if sha256(path) != expected_hash:
        raise ValueError(f"Archive hash mismatch: {filename}")
    yield from iter_csv_rows(path, date)
