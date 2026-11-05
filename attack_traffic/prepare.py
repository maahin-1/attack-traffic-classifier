"""Prepare a bounded, label-independent corrected-data subset from the local ZIP.

No endpoint identifiers are exported. Selection happens before label inspection;
all selected rows remain available to the audit, including invalid feature values.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
import os
import shutil
import tempfile
import zipfile
from datetime import datetime, timedelta
from pathlib import Path

from .audit import TIME_FIELDS, _dump, _sha


FEATURES = {
    "Flow Duration": ("flow_duration", "microseconds"),
    "Total Fwd Packet": ("total_fwd_packets", "count"),
    "Total Bwd packets": ("total_bwd_packets", "count"),
    "Total Length of Fwd Packet": ("total_fwd_bytes", "bytes"),
    "Total Length of Bwd Packet": ("total_bwd_bytes", "bytes"),
    "Fwd Packet Length Max": ("fwd_packet_length_max", "bytes"),
    "Fwd Packet Length Min": ("fwd_packet_length_min", "bytes"),
    "Fwd Packet Length Mean": ("fwd_packet_length_mean", "bytes"),
    "Fwd Packet Length Std": ("fwd_packet_length_std", "bytes"),
    "Bwd Packet Length Max": ("bwd_packet_length_max", "bytes"),
    "Bwd Packet Length Min": ("bwd_packet_length_min", "bytes"),
    "Bwd Packet Length Mean": ("bwd_packet_length_mean", "bytes"),
    "Bwd Packet Length Std": ("bwd_packet_length_std", "bytes"),
    "Flow IAT Mean": ("flow_iat_mean", "microseconds"),
    "Flow IAT Std": ("flow_iat_std", "microseconds"),
    "Flow IAT Max": ("flow_iat_max", "microseconds"),
    "Flow IAT Min": ("flow_iat_min", "microseconds"),
    "Fwd IAT Total": ("fwd_iat_total", "microseconds"),
    "Bwd IAT Total": ("bwd_iat_total", "microseconds"),
    "Active Mean": ("active_mean", "microseconds"),
    "Active Std": ("active_std", "microseconds"),
    "Active Max": ("active_max", "microseconds"),
    "Active Min": ("active_min", "microseconds"),
    "Idle Mean": ("idle_mean", "microseconds"),
    "Idle Std": ("idle_std", "microseconds"),
    "Idle Max": ("idle_max", "microseconds"),
    "Idle Min": ("idle_min", "microseconds"),
}
TIME_FORMAT = "%Y-%m-%d %H:%M:%S.%f"
DAYS = {"monday.csv", "tuesday.csv", "wednesday.csv", "thursday.csv", "friday.csv"}


def selected_record(archive_hash: str, member: str, record: int, denominator: int) -> bool:
    key = f"subset-v1:{archive_hash}:{member}:{record}".encode()
    return int.from_bytes(hashlib.blake2b(key, digest_size=8).digest(), "big") % denominator == 0


def prepare_subset(archive: str | Path, acquisition: str | Path, output: str | Path,
                   denominator: int = 100, max_rows: int = 50000, *, temporal_basis: str = "event_time") -> Path:
    if type(denominator) is not int or denominator < 1 or type(max_rows) is not int or max_rows < 1:
        raise ValueError("denominator and max_rows must be positive integers")
    if temporal_basis not in ("event_time", "capture_date"):
        raise ValueError("temporal_basis must be event_time or capture_date")
    archive, acquisition, output = Path(archive).resolve(), Path(acquisition).resolve(), Path(output).resolve()
    if output.exists():
        raise ValueError(f"Prepared subset already exists: {output}")
    provenance = json.loads(acquisition.read_text(encoding="utf-8"))
    archive_hash = _sha(archive)
    if provenance.get("sha256") != archive_hash:
        raise ValueError("Local archive does not match recorded acquisition SHA-256")
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".prepare-", dir=output.parent))
    try:
        rows, labels, counts = [], set(), {}
        fields = ["event_start", "event_end", "source_label", "attempted_category", *[item[0] for item in FEATURES.values()]]
        if temporal_basis == "capture_date":
            fields.extend(TIME_FIELDS)
        with zipfile.ZipFile(archive) as bundle:
            if set(bundle.namelist()) != DAYS or len(bundle.infolist()) != len(DAYS):
                raise ValueError("Archive must contain exactly the five inspected daily CSV members")
            if sum(info.file_size for info in bundle.infolist()) > 2 * 1024 ** 3:
                raise ValueError("Archive uncompressed size exceeds the inspected CSV profile")
            for member in sorted(DAYS):
                seen = kept = 0
                with bundle.open(member) as raw, io.TextIOWrapper(raw, encoding="utf-8-sig", newline="") as text:
                    reader = csv.DictReader(text)
                    headers = reader.fieldnames or []
                    if len(headers) != len(set(headers)) or not set(FEATURES).union({"Timestamp", "Label", "Attempted Category"}).issubset(headers):
                        raise ValueError(f"Unexpected or ambiguous source schema: {member}")
                    for number, row in enumerate(reader, 2):
                        seen += 1
                        if None in row or any(value is None for value in row.values()):
                            raise ValueError(f"Malformed CSV record {member}:{number}")
                        labels.add(row["Label"].strip())
                        if not selected_record(archive_hash, member, number, denominator):
                            continue
                        if len(rows) >= max_rows:
                            raise ValueError("Selected subset exceeds max_rows; increase the explicit cap or denominator")
                        entry = {canonical: row[source] for source, (canonical, _) in FEATURES.items()}
                        entry.update(event_start=row["Timestamp"].strip(), event_end="", source_label=row["Label"].strip(), attempted_category=row["Attempted Category"].strip())
                        if temporal_basis == "capture_date":
                            entry.update({field: "" for field in TIME_FIELDS})
                            entry.update(capture_date=row["Timestamp"][:10], source_timestamp=row["Timestamp"], origin_member=member, origin_record=str(number), timing_status="observed_utc_microsecond")
                        try:
                            start = datetime.strptime(entry["event_start"], TIME_FORMAT)
                            duration = float(entry["flow_duration"])
                            if math.isfinite(duration) and duration >= 0:
                                entry["event_end"] = (start + timedelta(microseconds=duration)).strftime(TIME_FORMAT)
                        except (ValueError, OverflowError):
                            pass  # Preserve selected invalid rows for the downstream audit.
                        rows.append((entry["capture_date"] if temporal_basis == "capture_date" else entry["event_start"], member, number, entry))
                        kept += 1
                counts[member] = {"source_rows": seen, "selected_rows": kept}
                print(f"Prepared {member}: selected {kept} of {seen}", flush=True)
        rows.sort(key=lambda item: item[:3])
        with (stage / "flows.csv").open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            writer.writerows(entry for _, _, _, entry in rows)
        label_map = {}
        for label in sorted(labels):
            benign = label == "BENIGN" or label.endswith(" - Attempted")
            label_map[label] = {"binary": 0 if benign else 1, "family": "benign" if benign else label}
        features = [item[0] for item in FEATURES.values()]
        preparation = {"schema_version": 1, "archive_sha256": archive_hash, "archive_bytes": archive.stat().st_size,
                       "algorithm": "BLAKE2b-64(subset-v1:archive_sha256:member:csv_record_number) modulo denominator == 0",
                       "denominator": denominator, "max_rows": max_rows, "selected_rows": len(rows), "by_member": counts,
                       "selection_note": "Label-independent deterministic subset; no balancing of validation/test; no full-data claim.",
                       "sorting": "event start, source member name, source CSV record number",
                       "end_time": "UTC start + Flow Duration in microseconds; malformed/negative values retained for audit",
                       "feature_policy": "27 corrected-release numeric statistics; original feature equivalence not yet verified",
                       "label_policy": "BENIGN and exact observed labels ending ' - Attempted' -> benign; remaining enumerated labels -> named attacks",
                       "source_label_values": sorted(labels)}
        _dump(stage / "preparation.json", preparation)
        preparation["temporal_basis"] = temporal_basis
        if temporal_basis == "capture_date":
            preparation["sorting"] = "capture date, source member name, source CSV record number; not within-day earliest event"
        _dump(stage / "preparation.json", preparation)
        config = {"version": 1, "output_dir": os.path.relpath(Path(__file__).resolve().parent.parent / "artifacts" / "corrected-subset-1pct", output),
                  "profile": "subset", "feature_allowlist": features, "feature_units": {item[0]: item[1] for item in FEATURES.values()},
                  "label_map_version": "cns2022-observed-attempted-benign-v1", "label_map": label_map,
                  "timestamp_format": TIME_FORMAT, "timezone": "UTC",
                  "boundaries": {"validation_start": "2017-07-05T00:00:00+00:00", "test_start": "2017-07-06T00:00:00+00:00"},
                  "datasets": [{"variant": "corrected", "release": f"CNS2022-CICIDS2017-{archive_hash[:12]}-subset-1-in-{denominator}",
                                "source_url": provenance["source_url"], "retrieved_at": provenance["retrieved_at"],
                                "license": provenance["license_status"], "files": ["flows.csv"],
                                "columns": {field: field for field in fields}, "preparation": preparation}],
                  "training": {"seed": 42, "n_estimators": 200, "max_depth": 12, "min_samples_leaf": 2, "n_jobs": 1,
                               "max_rows_per_variant": max_rows, "fpr_target": 0.01, "alert_budget": 100}}
        config["temporal_basis"] = temporal_basis
        if temporal_basis == "capture_date":
            config["boundaries"] = {"validation_start": "2017-07-05", "test_start": "2017-07-06"}
        _dump(stage / "config.json", config)
        stage.rename(output)
        return output
    except Exception:
        shutil.rmtree(stage)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--acquisition", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--denominator", type=int, default=100)
    parser.add_argument("--max-rows", type=int, default=50000)
    parser.add_argument("--temporal-basis", choices=["event_time", "capture_date"], default="event_time")
    args = parser.parse_args()
    print(prepare_subset(args.archive, args.acquisition, args.output, args.denominator, args.max_rows, temporal_basis=args.temporal_basis))


if __name__ == "__main__":
    main()
