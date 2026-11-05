"""Streaming data contracts, quality accounting and chronological split audit.

This stage deliberately does not train a model. CSV streams are merged by event
start time so the first eligible duplicate is retained consistently across files.
"""

from __future__ import annotations

import csv
import hashlib
import heapq
import json
import math
import platform
import re
import shutil
import sqlite3
import tempfile
import time
from collections import Counter
from contextlib import closing
from datetime import date, datetime, time as datetime_time, timezone
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .config import load_config

TIME_FIELDS = ["capture_date", "source_timestamp", "local_start_lower", "local_start_upper", "local_end_upper", "origin_member", "origin_record", "timing_status"]


def _date_key(value: str, name: str) -> datetime:
    try:
        parsed = date.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an ISO capture date (YYYY-MM-DD)") from exc
    # Internal ordering coordinate only; never exported as an event timestamp.
    return datetime.combine(parsed, datetime_time.min, timezone.utc)


def _name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")


def _dump(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _aware(value: str, name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{name} must include a timezone offset")
    return parsed.astimezone(timezone.utc)


def _feature_safe(name: str) -> bool:
    tokens = set(_name(name).split("_"))
    compact = "".join(_name(name).split("_"))
    return not (tokens & {"ip", "port", "ports", "timestamp", "time", "label", "labels", "id", "index", "row", "target", "prediction", "class", "family", "attack", "attempted", "effective", "category", "binary", "unnamed", "address", "identifier"}) and compact not in {"flowid", "srcip", "dstip", "sourceip", "destinationip", "srcport", "dstport", "sourceport", "destinationport", "rowindex", "rownumber", "attemptedcategory", "effectivecategory", "attackcategory", "attemptedattack", "effectiveattack"}


def _validate(config: dict) -> tuple[list[str], datetime, datetime, object]:
    if config.get("version") != 1:
        raise ValueError("Config version must be 1")
    features = config.get("feature_allowlist")
    if not isinstance(features, list) or not features or not all(isinstance(x, str) and x for x in features):
        raise ValueError("feature_allowlist must be a nonempty list of canonical names")
    if any(_name(x) != x or not _feature_safe(x) for x in features) or len(set(features)) != len(features):
        raise ValueError("feature_allowlist contains an identifier/label/time/port field, noncanonical name, or duplicate")
    units = config.get("feature_units", {})
    if not isinstance(units, dict) or any(not isinstance(units.get(x), str) or not units[x].strip() for x in features):
        raise ValueError("feature_units must document every allowed feature")
    if "protocol" in features and not config.get("protocol_justification"):
        raise ValueError("protocol requires protocol_justification")
    labels = config.get("label_map")
    if not isinstance(labels, dict) or not labels or not config.get("label_map_version"):
        raise ValueError("A nonempty label_map and label_map_version are required")
    for label, mapped in labels.items():
        if not isinstance(label, str) or not isinstance(mapped, dict) or type(mapped.get("binary")) is not int or mapped["binary"] not in (0, 1) or not isinstance(mapped.get("family"), str) or not mapped["family"].strip():
            raise ValueError(f"Invalid explicit binary/family mapping for {label!r}")
    bounds = config.get("boundaries", {})
    if not isinstance(bounds, dict):
        raise ValueError("boundaries must be an object")
    basis = config.get("temporal_basis", "event_time")
    if basis not in ("event_time", "capture_date"):
        raise ValueError("temporal_basis must be event_time or capture_date")
    boundary_parser = _date_key if basis == "capture_date" else _aware
    validation = boundary_parser(bounds.get("validation_start"), "validation_start")
    test = boundary_parser(bounds.get("test_start"), "test_start")
    if validation >= test:
        raise ValueError("validation_start must precede test_start")
    if not isinstance(config.get("timestamp_format"), str) or not config["timestamp_format"]:
        raise ValueError("timestamp_format must be declared")
    try:
        zone = None if basis == "capture_date" and config.get("timezone") == "unresolved" else timezone.utc if config.get("timezone") == "UTC" else ZoneInfo(config["timezone"])
    except (KeyError, ZoneInfoNotFoundError, TypeError, ValueError) as exc:
        raise ValueError("timezone must name an installed IANA timezone (UTC needs no tzdata)") from exc
    datasets = config.get("datasets")
    if not isinstance(datasets, list) or not datasets:
        raise ValueError("datasets must be a nonempty list")
    variants = []
    for dataset in datasets:
        if not isinstance(dataset, dict):
            raise ValueError("Each dataset must be an object")
        for key in ("variant", "release", "source_url", "retrieved_at", "license"):
            if not isinstance(dataset.get(key), str) or not dataset[key].strip():
                raise ValueError(f"Each dataset requires {key}")
        _aware(dataset["retrieved_at"], "retrieved_at")
        variants.append(dataset["variant"])
        if not isinstance(dataset.get("files"), list) or not dataset["files"]:
            raise ValueError("Each dataset requires a nonempty files list")
        if not all(isinstance(path, str) and path.strip() for path in dataset["files"]):
            raise ValueError("Dataset files must contain nonempty path strings")
        columns = dataset.get("columns")
        if not isinstance(columns, dict) or not columns:
            raise ValueError("Each dataset requires an explicit columns mapping")
        if not all(isinstance(k, str) and isinstance(v, str) and _name(v) == v and v for k, v in columns.items()):
            raise ValueError("Column mapping values must be canonical names")
        if len({_name(k) for k in columns}) != len(columns) or len(set(columns.values())) != len(columns):
            raise ValueError("Column mapping has normalized name collisions or duplicate canonical targets")
        timing_required = ["capture_date", "timing_status"] if basis == "capture_date" else ["event_start"]
        if not set(features + timing_required + ["source_label"]).issubset(columns.values()):
            raise ValueError("Column mapping must include required timing fields, source_label and every allowed feature")
        for raw, canonical in columns.items():
            if canonical in features and not _feature_safe(raw):
                raise ValueError(f"Identifier/label/time/port source column {raw!r} cannot map to a model feature")
    if len(set(variants)) != len(variants):
        raise ValueError("Dataset variants must be unique")
    return features, validation, test, zone


def _parse_time(value: str, fmt: str, zone: object) -> datetime:
    parsed = datetime.strptime(value.strip(), fmt)
    if parsed.tzinfo is None:
        # Reject ambiguous/nonexistent wall times rather than silently choosing a fold.
        first, second = parsed.replace(tzinfo=zone, fold=0), parsed.replace(tzinfo=zone, fold=1)
        if first.utcoffset() != second.utcoffset():
            raise ValueError("ambiguous or nonexistent local time")
        parsed = first
    return parsed.astimezone(timezone.utc)


def _partition(start: datetime, validation: datetime, test: datetime) -> str:
    return "train" if start < validation else "validation" if start < test else "test"


def _rows(path: Path, mapping: dict, config: dict, zone: object, file_info: dict):
    normalized = {_name(k): v for k, v in mapping.items()}
    previous = None
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.reader(stream)
        try:
            headers = next(reader)
        except StopIteration:
            raise ValueError(f"CSV has no header: {path.name}")
        keys = [_name(x) for x in headers]
        if len(keys) != len(set(keys)):
            raise ValueError(f"Duplicate normalized CSV columns: {path.name}")
        if set(keys) != set(normalized):
            raise ValueError(f"Schema mismatch in {path.name}; missing={sorted(set(normalized)-set(keys))}, unexpected={sorted(set(keys)-set(normalized))}")
        file_info["schema_fingerprint"] = hashlib.sha256(json.dumps(keys, separators=(",", ":")).encode()).hexdigest()
        file_info["row_count"] = 0
        for number, values in enumerate(reader, 2):
            file_info["row_count"] += 1
            if len(values) != len(keys):
                raise ValueError(f"Malformed CSV field count in {path.name} record {number}; repair input before auditing")
            row = {normalized[k]: v for k, v in zip(keys, values)}
            label = row["source_label"].strip()
            if label not in config["label_map"]:
                raise ValueError(f"Unexpected label {label!r} in {path.name} record {number}; extend label_map explicitly")
            capture_mode = config.get("temporal_basis") == "capture_date"
            if zone is None and (row.get("event_start", "").strip() or row.get("event_end", "").strip()):
                raise ValueError("Unresolved timezone requires blank UTC event_start/event_end; preserve local timing as interval metadata")
            try:
                start = _parse_time(row.get("event_start", ""), config["timestamp_format"], zone) if zone is not None else None
            except ValueError:
                start = None
            key = _date_key(row.get("capture_date"), "capture_date") if capture_mode else start
            if key is not None:
                if previous is not None and key < previous:
                    raise ValueError(f"Input {path.name} is not sorted by event_start at record {number}; sort each CSV chronologically first")
                previous = key
            # Invalid times sort first and never enter duplicate state.
            yield (key or datetime.min.replace(tzinfo=timezone.utc), number, row, start)


def _audit_variant(dataset: dict, config: dict, base: Path, output: Path, writer, feature_writer, database, features, validation, test, zone):
    variant = dataset["variant"]
    file_manifest = []
    streams = []
    paths = [(base / entry).resolve() for entry in dataset["files"]]
    if len(paths) != len(set(paths)):
        raise ValueError(f"Repeated input files for variant {variant}")
    for file_index, path in enumerate(paths):
        if not path.is_file():
            raise ValueError(f"Input CSV does not exist: {path}")
        entry = {"file_index": file_index, "name": path.name, "sha256": _sha(path)}
        file_manifest.append(entry)
        streams.append(_rows(path, dataset["columns"], config, zone, entry))
    heap = []

    def advance(index):
        item = next(streams[index], None)
        if item is not None:
            heapq.heappush(heap, (item[0], index, item[1], item[2], item[3]))

    for index in range(len(streams)):
        advance(index)
    counts = Counter()
    reasons = Counter()
    by_class = {}
    issues = Counter()
    support = {part: Counter() for part in ("train", "validation", "test")}
    binary_support = {part: Counter() for part in support}
    coverage = {part: {"first_start": None, "last_start": None} for part in support}
    incomplete = 0
    conflicting_source_labels = conflicting_binary_labels = 0
    capture_mode = config.get("temporal_basis") == "capture_date"
    while heap:
        _, index, number, row, start = heapq.heappop(heap)
        label = row["source_label"].strip()
        mapped = config["label_map"][label]
        # Configured file index distinguishes byte-identical input copies.
        # Hash and record number make references stable within this manifest.
        record_id = hashlib.sha256(f"{variant}:{index}:{file_manifest[index]['sha256']}:{number}".encode()).hexdigest()
        ordering = _date_key(row.get("capture_date"), "capture_date") if capture_mode else start
        part = _partition(ordering, validation, test) if ordering else "unassigned"
        errors = []
        if start is None and not capture_mode:
            errors.append("malformed_start_time")
        local_upper = local_end_upper = None
        if capture_mode:
            if not row.get("timing_status", "").strip():
                raise ValueError("Capture-date rows require an explicit timing_status")
            if start and start.date() != ordering.date():
                raise ValueError("UTC event start disagrees with declared capture date")
            if row.get("local_start_lower") or row.get("local_start_upper") or row.get("local_end_upper"):
                try:
                    local_lower = datetime.fromisoformat(row["local_start_lower"])
                    local_upper = datetime.fromisoformat(row["local_start_upper"])
                    if local_lower.tzinfo is not None or local_upper.tzinfo is not None or local_lower > local_upper or local_lower.date() != ordering.date() or local_upper.date() != ordering.date():
                        raise ValueError("invalid local bounds")
                    if row.get("local_end_upper"):
                        local_end_upper = datetime.fromisoformat(row["local_end_upper"])
                        if local_end_upper.tzinfo is not None or local_end_upper < local_upper:
                            raise ValueError("invalid local end bound")
                except (KeyError, ValueError) as exc:
                    raise ValueError("Invalid local timing interval; use naive local-clock ISO bounds within capture date") from exc
            elif start is None:
                raise ValueError("Capture-date row lacks both observed UTC timing and explicit local uncertainty bounds")
        end = None
        if "event_end" not in row or not row["event_end"].strip():
            incomplete += int(not (capture_mode and row.get("local_end_upper")))
        else:
            try:
                end = _parse_time(row["event_end"], config["timestamp_format"], zone)
            except ValueError:
                errors.append("malformed_end_time")
        if start and end and end < start:
            errors.append("invalid_duration")
        numbers = []
        for feature in features:
            try:
                value = float(row[feature])
            except ValueError:
                errors.append(f"malformed_feature:{feature}")
                continue
            if not math.isfinite(value):
                errors.append(f"nonfinite_feature:{feature}")
                kind = "nan_feature" if math.isnan(value) else "infinite_feature"
                issues[f"{part}|{label}|{kind}:{feature}"] += 1
            elif "duration" in feature and value < 0:
                errors.append("invalid_duration")
            numbers.append(0.0 if value == 0 else value)
        duplicate_id = ""
        disposition, reason = "retained", ""
        if errors:
            disposition, reason = "excluded", ";".join(sorted(set(errors)))
            for error in set(errors):
                issues[f"{part}|{label}|{error}"] += 1
        else:
            duplicate_id = hashlib.sha256(json.dumps(numbers, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
            if capture_mode and start is None and local_end_upper is None:
                disposition, reason = "quarantined", "unresolved_end_bound"
            elif start and end and any(start < boundary <= end for boundary in (validation, test)):
                disposition, reason = "quarantined", "spans_partition_boundary"
            elif capture_mode and local_end_upper and any(ordering.date() < boundary.date() and local_end_upper >= boundary.replace(tzinfo=None) for boundary in (validation, test)):
                disposition, reason = "quarantined", "possibly_spans_partition_boundary"
            elif (earlier := database.execute("SELECT source_label,binary_label FROM seen WHERE variant=? AND digest=?", (variant, duplicate_id)).fetchone()):
                disposition, reason = "quarantined", "later_duplicate"
                conflicting_source_labels += int(earlier[0] != label)
                conflicting_binary_labels += int(earlier[1] != mapped["binary"])
            else:
                database.execute("INSERT INTO seen VALUES (?, ?, ?, ?)", (variant, duplicate_id, label, mapped["binary"]))
        counts[disposition] += 1
        if reason:
            reasons[reason] += 1
        class_counts = by_class.setdefault(label, Counter())
        class_counts[disposition] += 1
        if disposition == "retained":
            feature_writer.writerow({"variant": variant, "record_id": record_id, **dict(zip(features, numbers))})
            support[part][mapped["family"]] += 1
            binary_support[part][str(mapped["binary"])] += 1
            if start:
                iso = start.isoformat()
                coverage[part]["first_start"] = min(coverage[part]["first_start"] or iso, iso)
                coverage[part]["last_start"] = max(coverage[part]["last_start"] or iso, iso)
            if capture_mode:
                day = row["capture_date"]
                coverage[part]["first_capture_date"] = min(coverage[part].get("first_capture_date", day), day)
                coverage[part]["last_capture_date"] = max(coverage[part].get("last_capture_date", day), day)
        writer.writerow({"variant": variant, "record_id": record_id, "source_file_index": index, "source_record": number, "event_start": start.isoformat() if start else "", "event_end": end.isoformat() if end else "", "source_label": label, "attempted_category": row.get("attempted_category", ""), "binary_label": mapped["binary"], "family": mapped["family"], "partition": part, "disposition": disposition, "reason": reason, "duplicate_group_id": duplicate_id, **{field: row.get(field, "") for field in TIME_FIELDS}})
        advance(index)
    total = sum(counts.values())
    quality = {"input_rows": total, "dispositions": {key: counts[key] for key in ("retained", "excluded", "quarantined")}, "reasons": dict(reasons), "by_source_label": by_class, "issues_by_partition_label": dict(issues), "incomplete_end_times": incomplete}
    quality.update(duplicate_conflicting_source_label_rows=conflicting_source_labels, duplicate_conflicting_binary_label_rows=conflicting_binary_labels)
    families = set().union(*(set(support[p]) for p in support))
    inventory = {"retained_family_support": support, "retained_binary_support": binary_support, "time_coverage": coverage, "families_unseen_in_train": sorted(families - set(support["train"])), "ready_for_binary_training": all(binary_support[p]["0"] and binary_support[p]["1"] for p in ("train", "validation")), "timing_note": "Start-time coverage is not evidence of complete capture days."}
    manifest = {key: dataset[key] for key in ("variant", "release", "source_url", "retrieved_at", "license")}
    if "preparation" in dataset:
        manifest["preparation"] = dataset["preparation"]
    manifest.update(files=file_manifest, input_rows=total)
    return manifest, quality, inventory


def run_audit(config_path: str | Path) -> Path:
    """Create a complete immutable audit directory or leave no published run.

    Paths in config resolve relative to its directory. Each CSV must be sorted
    by event start; multiple files are heap-merged. Disk-backed duplicate state
    avoids a Python set proportional to the full dataset population.
    """
    begun = time.perf_counter()
    config_path = Path(config_path).resolve()
    config = load_config(config_path)
    features, validation, test, zone = _validate(config)
    if not isinstance(config.get("output_dir"), str) or not config["output_dir"]:
        raise ValueError("output_dir is required")
    output = (config_path.parent / config["output_dir"]).resolve()
    if output.exists():
        raise ValueError(f"Run directory already exists: {output}; choose a new output_dir")
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".audit-", dir=output.parent))
    try:
        manifests, quality, inventory = [], {}, {}
        with closing(sqlite3.connect(stage / "dedup.sqlite")) as database, (stage / "splits.csv").open("w", newline="", encoding="utf-8") as stream, (stage / "retained_features.csv").open("w", newline="", encoding="utf-8") as feature_stream:
            database.execute("CREATE TABLE seen (variant TEXT, digest TEXT, source_label TEXT, binary_label INTEGER, PRIMARY KEY (variant,digest)) WITHOUT ROWID")
            fields = ["variant", "record_id", "source_file_index", "source_record", "event_start", "event_end", "source_label", "attempted_category", "binary_label", "family", "partition", "disposition", "reason", "duplicate_group_id", *TIME_FIELDS]
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            feature_writer = csv.DictWriter(feature_stream, fieldnames=["variant", "record_id", *features])
            feature_writer.writeheader()
            for dataset in config["datasets"]:
                adapter = dict(config)
                for key in ("timestamp_format", "timezone", "label_map", "label_map_version"):
                    if key in dataset:
                        adapter[key] = dataset[key]
                adapter["datasets"] = [dataset]
                _, _, _, adapter_zone = _validate(adapter)
                manifest, audit, coverage = _audit_variant(dataset, adapter, config_path.parent, stage, writer, feature_writer, database, features, validation, test, adapter_zone)
                manifest["timestamp_format"] = adapter["timestamp_format"]
                manifest["timezone"] = adapter["timezone"]
                manifest["label_map_version"] = adapter["label_map_version"]
                manifests.append(manifest)
                quality[dataset["variant"]] = audit
                inventory[dataset["variant"]] = coverage
        (stage / "dedup.sqlite").unlink()
        _dump(stage / "config.json", config)
        _dump(stage / "feature_list.json", {"features": features, "units": config["feature_units"], "protocol_justification": config.get("protocol_justification")})
        _dump(stage / "manifest.json", {"schema_version": 1, "stage": "data_audit_only", "datasets": manifests, "label_map_version": config["label_map_version"], "boundaries": config["boundaries"], "deduplication_policy": "first_eligible_chronological_feature_record_per_variant", "environment": {"python": platform.python_version(), "platform": platform.platform()}, "wall_seconds": time.perf_counter() - begun})
        manifest = json.loads((stage / "manifest.json").read_text())
        manifest["temporal_basis"] = config.get("temporal_basis", "event_time")
        if manifest["temporal_basis"] == "capture_date":
            manifest["deduplication_policy"] = "first_eligible_capture_date_then_prepared_source_order_per_variant; within-day earliest event is not established"
        _dump(stage / "manifest.json", manifest)
        _dump(stage / "quality.json", quality)
        _dump(stage / "inventory.json", inventory)
        lines = ["# Data foundation audit", "", "This is a data audit, not a trained model or detection-quality comparison.", "", "| Variant | Input | Retained | Excluded | Quarantined | Binary train/validation support |", "| --- | ---: | ---: | ---: | ---: | --- |"]
        for variant, audit in quality.items():
            counts = audit["dispositions"]
            lines.append(f"| {variant} | {audit['input_rows']} | {counts['retained']} | {counts['excluded']} | {counts['quarantined']} | {bool(inventory[variant]['ready_for_binary_training'])} |")
        lines.extend(["", "Inspect inventory.json before freezing training boundaries. Insufficient binary support blocks future fitting, not this inventory command.", "", "Duplicate groups use only the shared numeric feature allowlist, within each variant. Later eligible copies are quarantined. Boundary-spanning records are quarantined before duplicate eligibility. Inputs are streamed and each file must be chronological; ties use configured file order and source record number.", "", "Missing end times are counted; boundary overlap cannot be ruled out for these records. Start-time coverage does not establish complete capture days. Source labels and explicit family mappings remain available in the local split audit.", "", "Original/corrected populations may contain reconstructed flows. No one-to-one matching or label-only causal claim is made. No source/destination IP or port values are exported.", ""])
        if config.get("temporal_basis") == "capture_date":
            lines.extend(["Capture-date experiment: boundaries are dates, not matched UTC instants. Original missing AM/PM/timezone is preserved in local uncertainty intervals; blank event_start/end means unavailable UTC timing. Possible interval boundary crossings are quarantined. Deduplication retains the first eligible capture day and prepared source order, not an asserted earliest event within that day.", ""])
        (stage / "report.md").write_text("\n".join(lines), encoding="utf-8")
        stage.rename(output)
        return output
    except Exception:
        shutil.rmtree(stage)
        raise
