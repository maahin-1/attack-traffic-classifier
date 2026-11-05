"""Positional inspection of the original CICIDS2017 labelled-flow archive.

Inspection reports literal clock evidence. It neither supplies missing AM/PM
markers nor assigns a timezone. Duplicate source columns are never collapsed.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import math
import os
import re
import shutil
import tempfile
import time
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from .audit import _sha
from .prepare import FEATURES, selected_record


FEATURE_ALIASES = {source: source for source in FEATURES}
FEATURE_ALIASES.update({"Total Fwd Packet": "Total Fwd Packets", "Total Bwd packets": "Total Backward Packets", "Total Length of Fwd Packet": "Total Length of Fwd Packets", "Total Length of Bwd Packet": "Total Length of Bwd Packets"})
ORIGINAL_FEATURES = {FEATURE_ALIASES[source]: value for source, value in FEATURES.items()}
ORIGINAL_MEMBERS = frozenset("TrafficLabelling /" + name for name in (
    "Monday-WorkingHours.pcap_ISCX.csv", "Tuesday-WorkingHours.pcap_ISCX.csv", "Wednesday-workingHours.pcap_ISCX.csv", "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv", "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv", "Friday-WorkingHours-Morning.pcap_ISCX.csv", "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"))
_CLOCK = re.compile(r"^(\d{1,2})/(\d{1,2})/(\d{4})\s+(\d{1,2}):(\d{2})(?::(\d{2})(?:\.(\d+))?)?(?:\s*([AaPp][Mm]))?$")
ORIGINAL_LABEL_MAP = {label: {"binary": 0 if label == "BENIGN" else 1, "family": family} for label, family in {
    "BENIGN": "benign", "Bot": "Botnet", "DDoS": "DDoS", "DoS GoldenEye": "DoS GoldenEye", "DoS Hulk": "DoS Hulk", "DoS Slowhttptest": "DoS Slowhttptest", "DoS slowloris": "DoS Slowloris", "FTP-Patator": "FTP-Patator", "Heartbleed": "Heartbleed", "Infiltration": "Infiltration", "PortScan": "Portscan", "SSH-Patator": "SSH-Patator", "Web Attack \u2013 Brute Force": "Web Attack - Brute Force", "Web Attack \u2013 Sql Injection": "Web Attack - SQL Injection", "Web Attack \u2013 XSS": "Web Attack - XSS"}.items()}
LABEL_MAP_VERSION = "original-to-cns2022-families-v1"
TIME_FIELDS = ["event_start", "event_end", "capture_date", "local_start_lower", "local_start_upper", "local_end_upper", "source_timestamp", "origin_member", "origin_record", "timing_status"]


def _capture_date(member):
    weekday = Path(member).name.split("-", 1)[0].lower()
    dates = {"monday": "2017-07-03", "tuesday": "2017-07-04", "wednesday": "2017-07-05", "thursday": "2017-07-06", "friday": "2017-07-07"}
    if weekday not in dates:
        raise ValueError(f"Unknown original capture-day member: {member}")
    return dates[weekday]


def original_clock_interval(raw_timestamp, member, duration):
    """Return conservative naive-local bounds without claiming UTC alignment.

    Missing AM/PM covers both clock candidates. The upper bound includes the
    source's full represented second/minute, ending at its final microsecond.
    This assumes a represented time bin, not an unverified nearest-bin rounding.
    """
    clock = _clock_evidence(raw_timestamp)
    if not clock["valid_structure"] or not clock["valid_clock_range"]:
        raise ValueError(f"Malformed original timestamp {raw_timestamp!r} in {member}")
    date = clock["date_candidates"].get("day_month_year", {}).get("date")
    if date != _capture_date(member):
        raise ValueError(f"Original timestamp calendar date disagrees with capture-day member: {member}")
    hour, marker = clock["raw_hour"], clock["ampm"]
    fraction = clock["fraction"] or ""
    if len(fraction) > 6:
        raise ValueError("Original timestamp precision beyond microseconds is unsupported")
    if marker:
        if not 1 <= hour <= 12:
            raise ValueError("Explicit AM/PM hour must lie in1..12")
        candidates = [hour % 12 + (12 if marker == "PM" else 0)]
        status = "explicit_ampm"
    elif 1 <= hour <= 12:
        candidates = [hour % 12, hour % 12 + 12]
        status = "ambiguous_12h"
    else:
        candidates = [hour]
        status = "unambiguous_24h"
    midnight = datetime.fromisoformat(date)
    starts = [midnight + timedelta(hours=value, minutes=clock["minute"], seconds=clock["second"] or 0, microseconds=int(fraction.ljust(6, "0")) if fraction else 0) for value in candidates]
    precision_microseconds = 10 ** (6 - len(fraction)) if fraction else 1000000 if clock["second"] is not None else 60000000
    lower = min(starts)
    upper = max(starts) + timedelta(microseconds=precision_microseconds - 1)
    end_upper = ""
    try:
        duration_value = float(duration)
        if math.isfinite(duration_value) and duration_value >= 0:
            end_upper = (upper + timedelta(microseconds=math.ceil(duration_value))).isoformat(timespec="microseconds")
    except (ValueError, OverflowError):
        pass  # Keep invalid required numeric fields for the downstream audit.
    return {"event_start": "", "event_end": "", "capture_date": date, "local_start_lower": lower.isoformat(timespec="microseconds"), "local_start_upper": upper.isoformat(timespec="microseconds"), "local_end_upper": end_upper, "source_timestamp": raw_timestamp, "timing_status": f"{status}_{clock['precision']}"}


def _clock_evidence(value):
    """Parse literal components and both possible slash-date conventions."""
    matched = _CLOCK.fullmatch(value.strip())
    if not matched:
        return {"valid_structure": False}
    a, b, year, hour, minute, second, fraction, marker = matched.groups()
    a, b, year, hour, minute = map(int, (a, b, year, hour, minute))
    second = int(second) if second is not None else None
    result = {"valid_structure": True, "raw_hour": hour, "minute": minute, "second": second, "fraction": fraction, "ampm": marker.upper() if marker else None, "precision": "fractional_second" if fraction else "second" if second is not None else "minute", "valid_clock_range": 0 <= hour <= 23 and 0 <= minute <= 59 and (second is None or 0 <= second <= 59), "date_candidates": {}}
    for policy, day, month in (("day_month_year", a, b), ("month_day_year", b, a)):
        try:
            date = datetime(year, month, day)
            result["date_candidates"][policy] = {"date": date.date().isoformat(), "weekday": date.strftime("%A")}
        except ValueError:
            pass
    return result


def _headers(headers, member):
    stripped = [value.strip().lstrip("\ufeff") for value in headers]
    counts = Counter(stripped)
    duplicates = {key: count for key, count in counts.items() if count > 1}
    required = set(ORIGINAL_FEATURES) | {"Timestamp", "Label", "Fwd Header Length"}
    if len(headers) != 85 or not required.issubset(stripped) or duplicates != {"Fwd Header Length": 2}:
        raise ValueError(f"Unexpected original positional schema in {member}: expected85 columns and exactly two Fwd Header Length columns")
    indexes = {source: stripped.index(source) for source in required if source != "Fwd Header Length"}
    duplicate_indexes = [index for index, value in enumerate(stripped) if value == "Fwd Header Length"]
    return stripped, indexes, duplicate_indexes


def _archive_info(archive, acquisition):
    archive, acquisition = Path(archive).resolve(), Path(acquisition).resolve()
    try:
        provenance = json.loads(acquisition.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read original acquisition: {exc}") from exc
    archive_hash = _sha(archive)
    if not isinstance(provenance, dict) or provenance.get("sha256") != archive_hash:
        raise ValueError("Original archive SHA-256 differs from acquisition record")
    return archive, provenance, archive_hash


def _validate_members(bundle):
    members = [info.filename for info in bundle.infolist() if not info.is_dir()]
    if len(members) != len(ORIGINAL_MEMBERS) or set(members) != ORIGINAL_MEMBERS:
        raise ValueError("Original archive must contain exactly the eight inspected labelled-flow CSV members")
    if any(info.is_dir() and info.filename != "TrafficLabelling /" for info in bundle.infolist()):
        raise ValueError("Original archive contains an unexpected directory member")
    if sum(info.file_size for info in bundle.infolist()) > 2 * 1024 ** 3:
        raise ValueError("Original archive exceeds the inspected uncompressed size profile")


def inspect_original(archive: str | Path, acquisition: str | Path, output: str | Path, *, encoding="cp1252") -> Path:
    """Stream all source records and publish an immutable evidence JSON file.

    Numeric errors are counted, never silently removed. Source date interpretations
    remain candidates; literal hour counts cannot recover missing AM/PM markers.
    """
    begun = time.perf_counter()
    output = Path(output).resolve()
    if output.exists():
        raise ValueError(f"Original inspection already exists: {output}")
    archive, provenance, archive_hash = _archive_info(archive, acquisition)
    result = {"schema_version": 1, "stage": "original_literal_inventory", "archive_sha256": archive_hash, "archive_bytes": archive.stat().st_size, "source_url": provenance.get("source_url"), "encoding": encoding, "clock_policy": "unresolved: literal clock fields and slash-date candidate evidence only; no AM/PM or timezone inference", "feature_policy": "27 explicitly aliased numeric statistics; both duplicate Fwd Header Length columns omitted", "feature_aliases": {source: {"original_header": FEATURE_ALIASES[source], "canonical": canonical, "unit": unit} for source, (canonical, unit) in FEATURES.items()}, "members": {}, "total_rows": 0}
    clock_cache = {}
    with zipfile.ZipFile(archive) as bundle:
        _validate_members(bundle)
        for member in sorted(ORIGINAL_MEMBERS):
            counts = Counter()
            labels, hours, precision, markers, dates = Counter(), Counter(), Counter(), Counter(), Counter()
            label_hours = defaultdict(Counter)
            label_ranges = {}
            errors = Counter()
            error_rows_by_label = Counter()
            duplicates = Counter()
            examples = []
            valid_min = valid_max = None
            with bundle.open(member) as raw, io.TextIOWrapper(raw, encoding=encoding, errors="strict", newline="") as text:
                reader = csv.reader(text)
                try:
                    raw_headers = next(reader)
                except StopIteration:
                    raise ValueError(f"Original CSV member has no header: {member}")
                headers, indexes, duplicate_indexes = _headers(raw_headers, member)
                feature_indexes = [(source, indexes[source]) for source in ORIGINAL_FEATURES]
                for number, row in enumerate(reader, 2):
                    counts["source_rows"] += 1
                    if len(row) != len(headers):
                        raise ValueError(f"Malformed positional CSV field count in {member} record {number}: expected85, got{len(row)}")
                    label = row[indexes["Label"]].strip()
                    raw_timestamp = row[indexes["Timestamp"]].strip()
                    labels[label] += 1
                    if raw_timestamp not in clock_cache:
                        clock_cache[raw_timestamp] = _clock_evidence(raw_timestamp)
                    clock = clock_cache[raw_timestamp]
                    if not clock["valid_structure"]:
                        counts["malformed_timestamp_structure"] += 1
                    else:
                        hour = str(clock["raw_hour"])
                        hours[hour] += 1
                        label_hours[label][hour] += 1
                        precision[clock["precision"]] += 1
                        markers[clock["ampm"] or "missing"] += 1
                        if not clock["valid_clock_range"]:
                            counts["invalid_clock_range"] += 1
                        elif clock["raw_hour"] <= 12 and clock["ampm"] is None:
                            counts["hour_12_or_lower_without_ampm"] += 1
                        for policy, candidate in clock["date_candidates"].items():
                            dates[f"{policy}|{candidate['date']}|{candidate['weekday']}"] += 1
                        dmy = clock["date_candidates"].get("day_month_year")
                        if dmy and clock["valid_clock_range"]:
                            literal = f"{dmy['date']}T{clock['raw_hour']:02}:{clock['minute']:02}:{clock['second'] or 0:02}"
                            ranges = label_ranges.setdefault(label, {"first_literal_clock": literal, "last_literal_clock": literal})
                            ranges["first_literal_clock"] = min(ranges["first_literal_clock"], literal)
                            ranges["last_literal_clock"] = max(ranges["last_literal_clock"], literal)
                            valid_min = min(valid_min, literal) if valid_min else literal
                            valid_max = max(valid_max, literal) if valid_max else literal
                    left, right = (row[index].strip() for index in duplicate_indexes)
                    if left == right:
                        duplicates["text_equal"] += 1
                    else:
                        duplicates["text_unequal"] += 1
                        if len(examples) < 3:
                            examples.append({"source_record": number, "left": left, "right": right})
                    try:
                        a, b = float(left), float(right)
                        equal = a == b or (math.isnan(a) and math.isnan(b))
                        duplicates["numeric_equal" if equal else "numeric_unequal"] += 1
                    except ValueError:
                        duplicates["numeric_unparseable"] += 1
                    invalid = False
                    for source, index in feature_indexes:
                        try:
                            value = float(row[index])
                        except ValueError:
                            errors[f"malformed|{source}"] += 1
                            invalid = True
                            continue
                        if not math.isfinite(value):
                            errors[f"{'nan' if math.isnan(value) else 'infinite'}|{source}"] += 1
                            invalid = True
                        elif source == "Flow Duration" and value < 0:
                            errors["negative_duration|Flow Duration"] += 1
                            invalid = True
                    if invalid:
                        counts["rows_invalid_required_numeric"] += 1
                        error_rows_by_label[label] += 1
            member_result = {"source_rows": counts["source_rows"], "counts": dict(counts), "source_label_counts": dict(labels), "raw_hour_counts": dict(hours), "label_hour_counts": {label: dict(value) for label, value in label_hours.items()}, "label_literal_clock_ranges": label_ranges, "timestamp_precision_counts": dict(precision), "ampm_marker_counts": dict(markers), "date_candidate_counts": dict(dates), "literal_clock_min": valid_min, "literal_clock_max": valid_max, "required_numeric_issues": dict(errors), "rows_invalid_required_numeric_by_label": dict(error_rows_by_label), "duplicate_fwd_header_length": {"zero_based_positions": duplicate_indexes, "counts": dict(duplicates), "unequal_examples": examples, "policy": "both omitted from the27feature policy regardless of equality"}, "schema_fingerprint": hashlib.sha256(json.dumps(headers, separators=(",", ":")).encode()).hexdigest(), "column_count": len(headers)}
            result["members"][member] = member_result
            result["total_rows"] += counts["source_rows"]
            print(f"Inspected original {member}: {counts['source_rows']} rows; raw hours={dict(hours)}; labels={dict(labels)}", flush=True)
    result["wall_seconds"] = time.perf_counter() - begun
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=".original-inspect-", suffix=".json", dir=output.parent)
    os.close(descriptor)
    temporary = Path(name)
    try:
        temporary.write_text(json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
        temporary.rename(output)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return output


def prepare_original_subset(archive: str | Path, acquisition: str | Path, output: str | Path,
                            denominator: int = 100, max_rows: int = 50000) -> Path:
    """Prepare a capture-date subset with explicit unresolved clock intervals.

    Source padding is inventoried separately from flow records. Hash sampling is
    evaluated on every original ordinal before checking labels or emptiness, so
    removing technical padding cannot shift the sampling population ordinals.
    """
    if type(denominator) is not int or denominator < 1 or type(max_rows) is not int or max_rows < 1:
        raise ValueError("denominator and max_rows must be positive integers")
    output = Path(output).resolve()
    if output.exists():
        raise ValueError(f"Original prepared subset already exists: {output}")
    archive, provenance, archive_hash = _archive_info(archive, acquisition)
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".original-prepare-", dir=output.parent))
    try:
        rows, by_member, labels = [], {}, Counter()
        selected_labels = Counter()
        total = Counter()
        clock_cache = {}
        fields = [*TIME_FIELDS, "source_label", *[canonical for canonical, _ in ORIGINAL_FEATURES.values()]]
        with zipfile.ZipFile(archive) as bundle, (stage / "preparation_exclusions.csv").open("w", newline="", encoding="utf-8") as exclusion_stream:
            _validate_members(bundle)
            exclusions = csv.DictWriter(exclusion_stream, fieldnames=["origin_member", "origin_record", "source_label_class", "reason", "selected"])
            exclusions.writeheader()
            for member in sorted(ORIGINAL_MEMBERS):
                member_counts = Counter()
                expected_date = _capture_date(member)
                with bundle.open(member) as raw, io.TextIOWrapper(raw, encoding="cp1252", errors="strict", newline="") as text:
                    reader = csv.reader(text)
                    try:
                        headers, indexes, _ = _headers(next(reader), member)
                    except StopIteration:
                        raise ValueError(f"Original CSV member has no header: {member}")
                    for number, row in enumerate(reader, 2):
                        if len(row) != len(headers):
                            raise ValueError(f"Malformed positional CSV field count in {member} record{number}")
                        sampled = selected_record(archive_hash, member, number, denominator)
                        member_counts["source_input_rows"] += 1
                        if not any(value.strip() for value in row):
                            member_counts["source_empty_excluded_rows"] += 1
                            member_counts["selected_empty_rows" if sampled else "unsampled_empty_rows"] += 1
                            labels["<missing>"] += 1
                            if sampled:
                                selected_labels["<missing>"] += 1
                            exclusions.writerow({"origin_member": member, "origin_record": number, "source_label_class": "<missing>", "reason": "all_85_fields_empty_source_padding", "selected": sampled})
                            continue
                        label = row[indexes["Label"]].strip()
                        if label not in ORIGINAL_LABEL_MAP:
                            raise ValueError(f"Unknown nonempty original source label {label!r} in {member}:{number}; explicit mapping review required")
                        labels[label] += 1
                        raw_timestamp = row[indexes["Timestamp"]].strip()
                        if raw_timestamp not in clock_cache:
                            clock_cache[raw_timestamp] = _clock_evidence(raw_timestamp)
                        clock = clock_cache[raw_timestamp]
                        if not clock["valid_structure"] or not clock["valid_clock_range"] or clock["date_candidates"].get("day_month_year", {}).get("date") != expected_date:
                            raise ValueError(f"Invalid original clock/calendar evidence in {member}:{number}; cannot invent chronology")
                        member_counts["source_flow_rows"] += 1
                        if not sampled:
                            member_counts["unsampled_flow_rows"] += 1
                            continue
                        if len(rows) >= max_rows:
                            raise ValueError("Selected original subset exceeds max_rows; increase explicit cap or denominator")
                        entry = {canonical: row[indexes[source]] for source, (canonical, _) in ORIGINAL_FEATURES.items()}
                        entry.update(original_clock_interval(raw_timestamp, member, entry["flow_duration"]))
                        entry.update(origin_member=member, origin_record=number, source_label=label)
                        rows.append(entry)
                        selected_labels[label] += 1
                        member_counts["selected_flow_rows"] += 1
                for key in ("source_input_rows", "source_flow_rows", "source_empty_excluded_rows", "selected_empty_rows", "unsampled_empty_rows", "selected_flow_rows", "unsampled_flow_rows"):
                    member_counts[key] += 0
                    total[key] += member_counts[key]
                by_member[member] = dict(member_counts)
                print(f"Prepared original {member}: {member_counts['selected_flow_rows']} selectedflows, {member_counts['source_empty_excluded_rows']} source-padding exclusions", flush=True)
        rows.sort(key=lambda row: (row["capture_date"], row["origin_member"], row["origin_record"]))
        with (stage / "flows.csv").open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
        if total["source_input_rows"] != total["source_empty_excluded_rows"] + total["selected_flow_rows"] + total["unsampled_flow_rows"]:
            raise ValueError("Internal original source accounting mismatch")
        preparation = {"schema_version": 1, "archive_sha256": archive_hash, "archive_bytes": archive.stat().st_size, "encoding": "cp1252", "algorithm": "BLAKE2b-64(subset-v1:archive_sha256:member:csv_record_number) modulo denominator == 0", "denominator": denominator, "max_rows": max_rows, "selected_rows": len(rows), **dict(total), "by_member": by_member, "source_label_counts": dict(labels), "selected_source_label_counts": dict(selected_labels), "label_map_version": LABEL_MAP_VERSION, "source_label_values": sorted(label for label in labels if label != "<missing>"), "feature_aliases": {source: {"original_header": FEATURE_ALIASES[source], "canonical": canonical, "unit": unit} for source, (canonical, unit) in FEATURES.items()}, "feature_policy": "Same27numeric statistics as corrected release via explicit aliases; both duplicate Fwd Header Length columns omitted", "source_exclusion_policy": "Every all85fields-empty record is source padding, not a labelled flow; all original ordinals and selected flags are recorded in preparation_exclusions.csv; missing labels on otherwise nonempty records fail validation", "selection_note": "Hash selection is label-independent and evaluated before emptiness/label inspection on original source ordinals; no class balancing or held-out oversampling", "temporal_basis": "capture_date", "clock_policy": "DMY calendar date validated against member capture day; original timezone unresolved, so UTC event start/end are blank. Missing AM/PM uses both12hour candidates and the entire represented second/minute bin; naive local upper bound is inclusive. No labels are used for time inference", "end_time": "local_end_upper=latest candidate precision-bin endpoint+ceil(nonnegative finite Flow Duration microseconds); invalid numeric values remain in flows for downstream exclusion", "sorting": "capture_date, origin_member lexicographic, original numeric origin_record; no earliest-within-day claim", "deduplication_note": "Prepared source-order ties within a capture day may select different conflicting-label representatives than event-time order; apply the same capture-date/source-order policy to both variants", "label_policy": "BENIGN is binary0;15enumerated original raw labels explicitly mapped to binary/families, with Bot/PortScan/slowloris/WebAttack spelling aliases; no missing-label binary assignment", "flows_sha256": _sha(stage / "flows.csv"), "exclusions_sha256": _sha(stage / "preparation_exclusions.csv")}
        label_map = {label: dict(ORIGINAL_LABEL_MAP[label]) for label in sorted(labels) if label != "<missing>"}
        config = {"version": 1, "profile": "subset", "output_dir": os.path.relpath(Path(__file__).resolve().parent.parent / "artifacts" / "original-subset-capture-date", output), "temporal_basis": "capture_date", "timezone": "unresolved", "timestamp_format": "%Y-%m-%d %H:%M:%S.%f", "boundaries": {"validation_start": "2017-07-05", "test_start": "2017-07-06"}, "feature_allowlist": [canonical for canonical, _ in ORIGINAL_FEATURES.values()], "feature_units": {canonical: unit for canonical, unit in ORIGINAL_FEATURES.values()}, "label_map_version": LABEL_MAP_VERSION, "label_map": label_map, "datasets": [{"variant": "original", "release": f"CICIDS2017-GeneratedLabelledFlows-{archive_hash[:12]}-subset-1-in-{denominator}-capture-date", "source_url": provenance.get("source_url", ""), "retrieved_at": provenance.get("retrieved_at", ""), "license": provenance.get("license_status", ""), "files": ["flows.csv"], "columns": {field: field for field in fields}, "timezone": "unresolved", "preparation": preparation}], "training": {"seed": 42, "n_estimators": 200, "max_depth": 12, "min_samples_leaf": 2, "n_jobs": 1, "max_rows_per_variant": max_rows, "fpr_target": 0.01, "alert_budget": 100}}
        (stage / "preparation.json").write_text(json.dumps(preparation, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
        (stage / "config.json").write_text(json.dumps(config, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
        stage.rename(output)
        return output
    except Exception:
        shutil.rmtree(stage)
        raise
