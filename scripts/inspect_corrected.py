"""Inventory corrected CICIDS2017 ZIP contents without extraction or raw identifiers.

Every member is consumed to EOF, so zipfile checks each member's CRC. The scan
does not fit models, choose features from labels, or inspect detection scores.
"""

from __future__ import annotations

import argparse
from collections import Counter
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import stat
import tempfile
import time
import zipfile


EXPECTED_MEMBERS = {f"{day}.csv" for day in ("monday", "tuesday", "wednesday", "thursday", "friday")}
TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S.%f"
EXPECTED_SHA256 = "97fdb91d339e2d8cf5627f981b831e5e7e400b981c58181c451a38fd03c48883"
MAX_MEMBER_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def safe_members(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    members = archive.infolist()
    names = [member.filename for member in members]
    if len(names) != len(set(names)) or set(names) != EXPECTED_MEMBERS:
        raise ValueError("Archive must contain exactly the five expected daily CSV members")
    if sum(member.file_size for member in members) > MAX_TOTAL_BYTES:
        raise ValueError("Archive exceeds the 2 GiB uncompressed inventory ceiling")
    for member in members:
        name = PurePosixPath(member.filename)
        mode = member.external_attr >> 16
        if name.is_absolute() or ".." in name.parts or "\\" in member.filename or ":" in member.filename or stat.S_ISLNK(mode):
            raise ValueError("Unsafe archive member name/type")
        if member.is_dir() or member.flag_bits & 1 or member.file_size > MAX_MEMBER_BYTES:
            raise ValueError("Unexpected directory, encrypted member or oversized daily CSV")
        if member.compress_size == 0 or member.file_size / member.compress_size > 500:
            raise ValueError("Unexpected archive compression ratio")
    return sorted(members, key=lambda member: member.filename)


def inspect_member(archive: zipfile.ZipFile, member: zipfile.ZipInfo) -> dict:
    labels, categories, pairs, issues = Counter(), Counter(), {}, Counter()
    first = last = previous = None
    adjacent_inversions = 0
    total = 0
    with archive.open(member) as raw, io.TextIOWrapper(raw, encoding="utf-8-sig", newline="") as text:
        reader = csv.reader(text, strict=True)
        headers = next(reader, None)
        required = ("Timestamp", "Flow Duration", "Label", "Attempted Category")
        if not headers or len(set(headers)) != len(headers) or not set(required).issubset(headers):
            raise ValueError(f"Missing or duplicate required columns in {member.filename}")
        positions = {name: headers.index(name) for name in required}
        for values in reader:
            total += 1
            if len(values) != len(headers):
                issues["malformed_field_count"] += 1
                previous = None
                continue
            label = values[positions["Label"]].strip()
            category = values[positions["Attempted Category"]].strip()
            labels[label] += 1
            categories[category] += 1
            pairs.setdefault(label, Counter())[category] += 1
            try:
                event = datetime.strptime(values[positions["Timestamp"]].strip(), TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
            except ValueError:
                issues["timestamp_parse_failure"] += 1
                previous = None
            else:
                first = event if first is None else min(first, event)
                last = event if last is None else max(last, event)
                if previous is not None and event < previous:
                    adjacent_inversions += 1
                previous = event
            try:
                duration = float(values[positions["Flow Duration"]])
            except ValueError:
                issues["malformed_duration"] += 1
            else:
                if not math.isfinite(duration):
                    issues["nonfinite_duration"] += 1
                elif duration < 0:
                    issues["negative_duration"] += 1
                elif not duration.is_integer():
                    issues["noninteger_duration_microseconds"] += 1
        # csv.reader exhaustion consumes the underlying ZipExtFile completely.
        # zipfile raises BadZipFile at EOF if the stored CRC does not match.
    result = {
        "member": member.filename,
        "uncompressed_bytes": member.file_size,
        "compressed_bytes": member.compress_size,
        "crc32": f"{member.CRC:08x}",
        "crc_verified_complete_read": True,
        "column_count": len(headers),
        "schema_sha256": hashlib.sha256(json.dumps(headers, separators=(",", ":")).encode()).hexdigest(),
        "rows": total,
        "labels": labels,
        "attempted_categories": categories,
        "label_by_attempted_category": pairs,
        "first_start_utc": first.isoformat() if first else None,
        "last_start_utc": last.isoformat() if last else None,
        "adjacent_start_time_inversions": adjacent_inversions,
        "issues": dict(issues),
    }
    print(json.dumps({key: result[key] for key in ("member", "rows", "labels", "attempted_categories", "adjacent_start_time_inversions", "issues")}, sort_keys=True), flush=True)
    return result


def inspect(archive_path: Path, output: Path) -> Path:
    started = time.perf_counter()
    if output.exists():
        raise ValueError(f"Inventory already exists: {output}; choose a new output")
    archive_digest = digest(archive_path)
    if archive_digest != EXPECTED_SHA256:
        raise ValueError("Archive SHA-256 differs from the explicitly selected downloaded snapshot")
    csv.field_size_limit(1024 * 1024)
    with zipfile.ZipFile(archive_path) as archive:
        members = safe_members(archive)
        inventory = [inspect_member(archive, member) for member in members]
    result = {
        "schema_version": 1,
        "archive_name": archive_path.name,
        "archive_sha256": archive_digest,
        "archive_bytes": archive_path.stat().st_size,
        "inspected_at_utc": datetime.now(timezone.utc).isoformat(),
        "timestamp_format": TIMESTAMP_FORMAT,
        "timezone": "UTC (maintainer documented)",
        "duration_unit": "microseconds (maintainer BasicFlow.java)",
        "members": inventory,
        "total_rows": sum(member["rows"] for member in inventory),
        "total_uncompressed_bytes": sum(member["uncompressed_bytes"] for member in inventory),
        "all_member_crcs_verified": True,
        "wall_seconds": time.perf_counter() - started,
        "scope": "Complete streaming data inventory; no extraction, model fitting or score inspection. Adjacent inversions count only consecutive successfully parsed CSV records.",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".inventory-", suffix=".json", dir=output.parent)
    stage = Path(temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")
        stage.rename(output)
    finally:
        stage.unlink(missing_ok=True)
    print(f"Inventory: {output} ({result['total_rows']} rows; CRCs verified)", flush=True)
    return output


def main() -> int:
    base = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, default=base / "data/cns2022/CICIDS2017_improved.zip")
    parser.add_argument("--output", type=Path, default=base / "data/cns2022/inventory.json")
    args = parser.parse_args()
    try:
        inspect(args.archive.resolve(), args.output.resolve())
    except (ValueError, OSError, csv.Error, zipfile.BadZipFile) as error:
        parser.exit(1, f"Inventory failed: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
