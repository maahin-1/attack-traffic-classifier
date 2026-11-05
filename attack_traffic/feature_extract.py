"""Pinned, validation-only raw feature extraction on immutable audited cohorts."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import math
import shutil
import struct
import tempfile
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

from .original import ORIGINAL_FEATURES, ORIGINAL_MEMBERS, _archive_info, _headers, _validate_members
from .prepare import DAYS, FEATURES


RAW_EXTRA_FEATURES = {f"{direction} IAT {stat}": (f"{direction.lower()}_iat_{stat.lower()}", "microseconds") for direction in ("Fwd", "Bwd") for stat in ("Mean", "Std", "Max", "Min")}
DERIVED_FEATURES = {
    "fwd_packet_fraction": {"kind": "derived", "unit": "dimensionless", "definition": "total_fwd_packets / (total_fwd_packets + total_bwd_packets); zero denominator -> 0"},
    "fwd_byte_fraction": {"kind": "derived", "unit": "dimensionless", "definition": "total_fwd_bytes / (total_fwd_bytes + total_bwd_bytes); zero denominator -> 0"},
    "fwd_bytes_per_packet": {"kind": "derived", "unit": "bytes/packet", "definition": "total_fwd_bytes / total_fwd_packets; zero denominator -> 0"},
    "bwd_bytes_per_packet": {"kind": "derived", "unit": "bytes/packet", "definition": "total_bwd_bytes / total_bwd_packets; zero denominator -> 0"},
}
EXTRA_FEATURES = {canonical: {"kind": "raw", "unit": unit, "source_header": source} for source, (canonical, unit) in RAW_EXTRA_FEATURES.items()} | DERIVED_FEATURES
_SOURCE_FILES = ("config.json", "manifest.json", "audit/manifest.json", "audit/splits.csv", "audit/retained_features.csv")
_META = ["variant", "record_id", "partition", "disposition", "duplicate_group_id"]
_DIAGNOSTIC_FIELDS = ["variant", "base_duplicate_group_id", "rows", "binary_conflict", "binary_minority_label_error_lower_bound", "valid_raw8_rows", "invalid_raw8_rows", "raw8_refined_group_count", "raw8_refined_binary_conflict_group_count", "raw8_refined_binary_minority_label_error_lower_bound", "derived4_refined_group_count", "complete_refinement"]


def _sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _object_sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _json(path):
    try:
        result = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read feature-extraction source {path}: {exc}") from exc
    if not isinstance(result, dict):
        raise ValueError(f"Feature-extraction JSON must contain an object: {path}")
    return result


def _csv(path, required):
    with Path(path).open(newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        fields = reader.fieldnames or []
        if len(fields) != len(set(fields)) or not set(required).issubset(fields):
            raise ValueError(f"Feature-extraction CSV schema mismatch: {path}")
        for row in reader:
            if None in row or any(value is None for value in row.values()):
                raise ValueError(f"Malformed feature-extraction source CSV: {path}")
            yield row


def _write_csv(path, fields, rows):
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _dump(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


def _feature_hash(values):
    return hashlib.sha256(json.dumps([0.0 if value == 0 else value for value in values], separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _group_stats(groups):
    stats = {"feature_group_count": len(groups), "duplicate_group_count": 0, "binary_conflict_group_count": 0, "binary_conflict_group_rows": 0, "binary_minority_label_error_lower_bound": 0}
    for group in groups.values():
        labels = Counter(row["binary_label"] for row in group)
        stats["duplicate_group_count"] += int(len(group) > 1)
        if len(labels) > 1:
            stats["binary_conflict_group_count"] += 1
            stats["binary_conflict_group_rows"] += len(group)
            stats["binary_minority_label_error_lower_bound"] += min(labels.values())
    return stats


def _derived(base):
    names = ("total_fwd_packets", "total_bwd_packets", "total_fwd_bytes", "total_bwd_bytes")
    values = [base[name] for name in names]
    if not all(math.isfinite(value) and value >= 0 for value in values):
        return {name: None for name in DERIVED_FEATURES}, "derived inputs require finite nonnegative packet and byte counts"
    fwd, bwd, fwd_bytes, bwd_bytes = values
    pairs = ((fwd, fwd + bwd), (fwd_bytes, fwd_bytes + bwd_bytes), (fwd_bytes, fwd), (bwd_bytes, bwd))
    result = {}
    for name, (numerator, denominator) in zip(DERIVED_FEATURES, pairs):
        if not math.isfinite(denominator):
            result[name] = None
            continue
        value = numerator / denominator if denominator else 0.0
        result[name] = value if math.isfinite(value) and value >= 0 else None
    return result, "nonfinite derived value" if any(value is None for value in result.values()) else None


def extract_features(source_run: str | Path, original_archive: str | Path, original_acquisition: str | Path,
                     corrected_archive: str | Path, corrected_acquisition: str | Path,
                     output_dir: str | Path) -> Path:
    """Extract fixed 8 raw + 4 derived features; never fit or change a cohort.

    Only eligible train/validation source ordinals are interpreted. Test-only ZIP
    members are never opened. Every opened member is consumed to EOF for CRC
    verification, without interpreting unrequested source labels/features.
    Invalid retained extras publish failed_extra_validation diagnostics, retaining
    every row/ID, so downstream fitting must fail closed rather than drop records.
    """
    source, output = Path(source_run).resolve(), Path(output_dir).resolve()
    if not source.is_dir() or output.exists() or output.is_relative_to(source):
        raise ValueError("Feature extraction needs an existing frozen source and a new external output directory")
    hashes = {name: _sha(source / name) for name in _SOURCE_FILES}
    config, manifest, audit_manifest = (_json(source / name) for name in ("config.json", "manifest.json", "audit/manifest.json"))
    if config.get("version") != 1 or manifest.get("schema_version") != 1 or audit_manifest.get("schema_version") != 1:
        raise ValueError("Unsupported feature-extraction source schema")
    base_names = [canonical for canonical, _ in FEATURES.values()]
    if config.get("feature_allowlist") != base_names or manifest.get("feature_allowlist") != base_names:
        raise ValueError("EXP004 requires the exact frozen ordered27feature policy")
    if config.get("feature_units") != {canonical: unit for canonical, unit in FEATURES.values()}:
        raise ValueError("Frozen base-feature units differ from the declared extraction policy")
    if manifest.get("datasets") != audit_manifest.get("datasets") or manifest.get("boundaries") != config.get("boundaries") or audit_manifest.get("boundaries") != config.get("boundaries"):
        raise ValueError("Frozen source manifests/config controls disagree")
    if manifest.get("config_sha256") is not None and manifest["config_sha256"] != _object_sha(config):
        raise ValueError("Frozen source config hash mismatch")
    datasets = config.get("datasets")
    if not isinstance(datasets, list) or len(datasets) != 2 or any(not isinstance(dataset, dict) for dataset in datasets):
        raise ValueError("EXP004 requires one original and one corrected dataset")
    datasets = {dataset.get("variant"): dataset for dataset in datasets}
    if set(datasets) != {"original", "corrected"}:
        raise ValueError("EXP004 requires exactly original/corrected variant names")
    archive_inputs = {"original": (original_archive, original_acquisition), "corrected": (corrected_archive, corrected_acquisition)}
    archives = {}
    archive_provenance = {}
    for variant, (archive, acquisition) in archive_inputs.items():
        path, acquisition_record, archive_hash = _archive_info(archive, acquisition)
        expected_hash = datasets[variant].get("preparation", {}).get("archive_sha256")
        if not expected_hash or expected_hash != archive_hash:
            raise ValueError(f"{variant} archive does not match the frozen dataset preparation hash")
        archives[variant] = path
        archive_provenance[variant] = {"archive_sha256": archive_hash, "acquisition_sha256": _sha(acquisition), "path": str(path)}
    records = []
    targets = {variant: defaultdict(lambda: defaultdict(list)) for variant in datasets}
    ids = set()
    populations = {dataset["variant"]: dataset for dataset in manifest["datasets"]}
    eligible_fields = ["partition", "disposition", "reason", "variant", "record_id", "source_file_index", "source_record", "source_label", "family", "binary_label", "duplicate_group_id", "origin_member", "origin_record"]
    for row in _csv(source / "audit/splits.csv", eligible_fields):
        # Do not interpret test labels, features, source origins, or IDs.
        if row["partition"] == "test":
            continue
        if row["partition"] not in ("train", "validation"):
            continue
        if row["disposition"] != "retained" and not (row["disposition"] == "quarantined" and row["reason"] == "later_duplicate"):
            continue
        variant, identifier = row["variant"], row["record_id"]
        if variant not in targets or not identifier or identifier in ids:
            raise ValueError("Unknown variant or duplicate/empty eligible extraction record ID")
        ids.add(identifier)
        try:
            file_index, source_record = int(row["source_file_index"]), int(row["source_record"])
            file_hash = populations[variant]["files"][file_index]["sha256"]
        except (ValueError, KeyError, TypeError, IndexError) as exc:
            raise ValueError("Frozen extraction record has an invalid prepared-source reference") from exc
        if file_index < 0 or source_record < 2 or identifier != hashlib.sha256(f"{variant}:{file_index}:{file_hash}:{source_record}".encode()).hexdigest():
            raise ValueError("Frozen record ID does not match its prepared-source hash and ordinal")
        try:
            ordinal = int(row["origin_record"])
        except ValueError as exc:
            raise ValueError("Frozen raw origin ordinal must be an integer") from exc
        allowed = ORIGINAL_MEMBERS if variant == "original" else DAYS
        if ordinal < 2 or row["origin_member"] not in allowed:
            raise ValueError("Frozen source origin is outside the pinned inspected archive")
        if row["binary_label"] not in ("0", "1"):
            raise ValueError("Eligible source binary label is invalid")
        mapping = datasets[variant].get("label_map", config.get("label_map", {}))
        if row["source_label"] not in mapping or mapping[row["source_label"]].get("binary") != int(row["binary_label"]) or mapping[row["source_label"]].get("family") != row["family"]:
            raise ValueError("Frozen eligible label mapping mismatch")
        entry = dict(row, binary_label=int(row["binary_label"]), extras={}, invalid=[], base_values=None)
        records.append(entry)
        targets[variant][row["origin_member"]][ordinal].append(entry)
    if not records:
        raise ValueError("Frozen source contains no eligible train/validation rows")
    invalid_rows = []
    opened_members = {variant: [] for variant in datasets}
    for variant in ("original", "corrected"):
        with zipfile.ZipFile(archives[variant]) as bundle:
            if variant == "original":
                _validate_members(bundle)
            elif len(bundle.infolist()) != len(DAYS) or set(bundle.namelist()) != DAYS or sum(member.file_size for member in bundle.infolist()) > 2 * 1024 ** 3:
                raise ValueError("Corrected archive differs from inspected five-member CSV profile")
            for member, requested in sorted(targets[variant].items()):
                opened_members[variant].append(member)
                with bundle.open(member) as raw, io.TextIOWrapper(raw, encoding="cp1252" if variant == "original" else "utf-8-sig", errors="strict", newline="") as text:
                    reader = csv.reader(text)
                    try:
                        header = next(reader)
                    except StopIteration:
                        raise ValueError(f"Pinned raw source member is empty: {member}")
                    if variant == "original":
                        stripped, _, _ = _headers(header, member)
                        base_map = ORIGINAL_FEATURES
                    else:
                        stripped = [name.strip() for name in header]
                        if len(stripped) != len(set(stripped)):
                            raise ValueError("Corrected raw schema has duplicate normalized header names")
                        base_map = FEATURES
                    required = set(base_map) | set(RAW_EXTRA_FEATURES) | {"Label", "Timestamp"}
                    if not required.issubset(stripped):
                        raise ValueError(f"Raw source is missing fixed feature headers: {member}")
                    positions = {name: stripped.index(name) for name in required}
                    found = set()
                    for ordinal, raw_row in enumerate(reader, 2):
                        if ordinal not in requested:
                            continue
                        if len(raw_row) != len(header):
                            raise ValueError(f"Requested raw source record has malformed field count: {member}:{ordinal}")
                        found.add(ordinal)
                        try:
                            base_values = [float(raw_row[positions[name]]) for name in base_map]
                        except ValueError as exc:
                            raise ValueError("Eligible raw source base feature is not numeric") from exc
                        if not all(math.isfinite(value) for value in base_values):
                            raise ValueError("Eligible raw source base feature is nonfinite")
                        base_values = [0.0 if value == 0 else value for value in base_values]
                        base_hash = _feature_hash(base_values)
                        base = dict(zip(base_names, base_values))
                        derived, derived_error = _derived(base)
                        extra_values, extra_invalid = {}, []
                        for raw_name, (canonical, _) in RAW_EXTRA_FEATURES.items():
                            literal = raw_row[positions[raw_name]]
                            try:
                                value = float(literal)
                                valid = math.isfinite(value) and value >= 0
                            except ValueError:
                                valid, value = False, None
                            extra_values[canonical] = 0.0 if valid and value == 0 else value if valid else literal
                            if not valid:
                                extra_invalid.append((canonical, literal, "raw directional IAT statistic must be finite and nonnegative"))
                        for canonical, value in derived.items():
                            extra_values[canonical] = value if value is not None else ""
                            if value is None:
                                extra_invalid.append((canonical, "", derived_error))
                        for record in requested[ordinal]:
                            if raw_row[positions["Label"]].strip() != record["source_label"] or base_hash != record["duplicate_group_id"]:
                                raise ValueError(f"Raw label/base27 hash does not match frozen reference: {variant}:{member}:{ordinal}")
                            if record.get("source_timestamp") and raw_row[positions["Timestamp"]].strip() != record["source_timestamp"]:
                                raise ValueError("Raw literal timestamp differs from frozen source metadata")
                            record["base_values"], record["extras"] = base_values, dict(extra_values)
                            record["invalid"] = list(extra_invalid)
                            for name, literal, reason in extra_invalid:
                                invalid_rows.append({"variant": variant, "record_id": record["record_id"], "partition": record["partition"], "disposition": record["disposition"], "feature": name, "value": literal, "reason": reason})
                    if found != set(requested):
                        raise ValueError(f"Pinned raw source is missing requested ordinals: {member}")
                print(f"Extracted fixed extras {variant}/{member}: {sum(len(value) for value in requested.values())} eligible train/validation records", flush=True)
    retained = {record["record_id"]: record for record in records if record["disposition"] == "retained"}
    found_retained = set()
    for row in _csv(source / "audit/retained_features.csv", ["variant", "record_id", *base_names]):
        if row["record_id"] not in retained:
            continue  # Includes every test feature row, before numeric conversion.
        identifier = row["record_id"]
        record = retained[identifier]
        if identifier in found_retained or row["variant"] != record["variant"]:
            raise ValueError("Frozen retained base-feature join has duplicate/mismatched IDs")
        try:
            base_values = [float(row[name]) for name in base_names]
        except ValueError as exc:
            raise ValueError("Frozen retained base feature is nonnumeric") from exc
        if not all(math.isfinite(value) for value in base_values) or _feature_hash(base_values) != record["duplicate_group_id"] or base_values != record["base_values"]:
            raise ValueError("Raw base27 values differ from immutable retained feature values")
        found_retained.add(identifier)
    if found_retained != set(retained):
        raise ValueError("Frozen retained feature artifact is missing eligible records")
    cohorts = {}
    for variant in ("original", "corrected"):
        cohorts[variant] = {}
        for partition in ("train", "validation"):
            rows = [record for record in records if record["variant"] == variant and record["partition"] == partition and record["disposition"] == "retained"]
            if not rows:
                raise ValueError("Feature extraction requires nonempty frozen training/validation cohorts for each release")
            matrix_digest = hashlib.sha256()
            for record in rows:
                matrix_digest.update(struct.pack("<" + "d" * len(base_names), *record["base_values"]))
            cohorts[variant][partition] = {"rows": len(rows), "ordered_record_ids_sha256": _object_sha([record["record_id"] for record in rows]), "ordered_duplicate_group_ids_sha256": _object_sha([record["duplicate_group_id"] for record in rows]), "labels_and_families_sha256": _object_sha([(str(record["binary_label"]), record["source_label"], record["family"]) for record in rows]), "feature_matrix_sha256": matrix_digest.hexdigest()}
    retained_invalid = {row["record_id"] for row in invalid_rows if row["disposition"] == "retained"}
    invalid_ids = {row["record_id"] for row in invalid_rows}
    summary = {"schema_version": 1, "status": "failed_extra_validation" if retained_invalid else "ok", "feature_order": list(EXTRA_FEATURES), "invalid_retained_rows": len(retained_invalid), "invalid_retained_feature_values": sum(row["disposition"] == "retained" for row in invalid_rows), "invalid_diagnostic_rows": len(invalid_ids), "variants": {}, "scope": "Only frozen eligible train/validation rows; no test extraction, label interpretation, fitting, cohort changes, duplicate restoration or relabeling", "invalid_policy": "Any invalid retained extra blocks downstream fitting. Invalid quarantined diagnostic rows make the complete raw8 refinement comparison unknown rather than silently changing its population."}
    diagnostics = []
    for variant in ("original", "corrected"):
        rows = [record for record in records if record["variant"] == variant]
        groups = defaultdict(list)
        refined_groups = defaultdict(list)
        invalid_raw_ids = set()
        derived_splits = 0
        for record in rows:
            groups[record["duplicate_group_id"]].append(record)
            if any(name in {canonical for canonical, _ in RAW_EXTRA_FEATURES.values()} for name, _, _ in record["invalid"]):
                invalid_raw_ids.add(record["record_id"])
            else:
                refined_groups[(record["duplicate_group_id"], *[record["extras"][canonical] for canonical, _ in RAW_EXTRA_FEATURES.values()])].append(record)
        for digest, group in sorted(groups.items()):
            labels = Counter(record["binary_label"] for record in group)
            expanded = defaultdict(list)
            derived_keys = set()
            invalid_raw_count = 0
            for record in group:
                derived_keys.add(tuple(record["extras"][name] for name in DERIVED_FEATURES))
                if record["record_id"] in invalid_raw_ids:
                    invalid_raw_count += 1
                else:
                    expanded[tuple(record["extras"][canonical] for canonical, _ in RAW_EXTRA_FEATURES.values())].append(record)
            derived_splits += max(0, len(derived_keys) - 1)
            if len(group) > 1:
                refined = _group_stats(expanded)
                diagnostics.append({"variant": variant, "base_duplicate_group_id": digest, "rows": len(group), "binary_conflict": len(labels) > 1, "binary_minority_label_error_lower_bound": min(labels.values()) if len(labels) > 1 else 0, "valid_raw8_rows": len(group) - invalid_raw_count, "invalid_raw8_rows": invalid_raw_count, "raw8_refined_group_count": refined["feature_group_count"] if not invalid_raw_count else None, "raw8_refined_binary_conflict_group_count": refined["binary_conflict_group_count"] if not invalid_raw_count else None, "raw8_refined_binary_minority_label_error_lower_bound": refined["binary_minority_label_error_lower_bound"] if not invalid_raw_count else None, "derived4_refined_group_count": len(derived_keys), "complete_refinement": not bool(invalid_raw_count)})
        if derived_splits:
            raise ValueError("Derived features unexpectedly split an exact base-feature group; extraction is inconsistent")
        summary["variants"][variant] = {"eligible_rows": len(rows), "retained_rows": sum(record["disposition"] == "retained" for record in rows), "later_duplicate_rows": sum(record["disposition"] != "retained" for record in rows), "invalid_raw8_rows": len(invalid_raw_ids), "refinement_status": "incomplete_invalid_extras" if invalid_raw_ids else "complete", "before": _group_stats(groups), "after_raw8": None if invalid_raw_ids else _group_stats(refined_groups), "derived4_splits_exact_base_groups": derived_splits}
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".feature-extract-", dir=output.parent))
    try:
        _write_csv(stage / "extended_features.csv", [*_META, *EXTRA_FEATURES], [{**{name: record[name] for name in _META}, **record["extras"]} for record in records])
        _write_csv(stage / "invalid_features.csv", ["variant", "record_id", "partition", "disposition", "feature", "value", "reason"], invalid_rows)
        _write_csv(stage / "diagnostic_group_summary.csv", _DIAGNOSTIC_FIELDS, diagnostics)
        _dump(stage / "summary.json", summary)
        lines = ["# Fixed extra-feature extraction and collision refinement", "", f"Status: {summary['status']}. Extraction preserves every eligible train/validation record and its source order. No models are fitted and no original quarantine is changed.", "", "The fixed block adds eight raw directional IAT statistics in microseconds plus four derived packet/byte measures. Denominators equal to zero produce zero; packet/byte inputs and raw IAT extras must be finite and nonnegative. An invalid retained extra blocks all downstream fits instead of dropping rows.", "", "Only referenced train/validation ordinals are interpreted. Test-only members are never opened; other records in opened members are consumed without label/feature conversion to verify ZIP CRCs. Archive SHA-256, raw source labels, literal source timestamps, base27 hashes and retained base27 values are checked against immutable references.", "", "| Variant | Eligible train/validation rows | Base groups | Base binary conflicts | Base minority-label bound | Raw8 refinement status | Refined groups | Refined binary conflicts | Refined minority-label bound |", "| --- | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: |"]
        for variant, value in summary["variants"].items():
            before, after = value["before"], value["after_raw8"]
            numbers = (variant, value["eligible_rows"], before["feature_group_count"], before["binary_conflict_group_count"], before["binary_minority_label_error_lower_bound"], value["refinement_status"], after["feature_group_count"] if after else "unknown", after["binary_conflict_group_count"] if after else "unknown", after["binary_minority_label_error_lower_bound"] if after else "unknown")
            lines.append("| " + " | ".join(map(str, numbers)) + " |")
        lines.extend(["", "Refinement bounds describe only eligible selected train/validation labels before duplicate quarantine. They are not test outcomes, evidence of correct labels, estimates of detector improvement, or permission to restore quarantined records. Invalid raw8 diagnostics make complete-population refinement bounds unknown. The four derived measures cannot split exact existing27feature ties; that invariant is checked explicitly.", "", "All raw archive endpoint columns remain private and are not exported. Output IDs/hashes reference existing records and feature groups. Original unresolved clocks remain metadata; these features make no new timestamp alignment assumption.", ""])
        (stage / "report.md").write_text("\n".join(lines), encoding="utf-8")
        if any(_sha(source / name) != expected for name, expected in hashes.items()):
            raise ValueError("Frozen source changed during extra-feature extraction")
        _dump(stage / "provenance.json", {"schema_version": 1, "source_run": str(source), "source_files": hashes, "archives": archive_provenance, "cohorts": cohorts, "feature_order": list(EXTRA_FEATURES), "feature_definitions": EXTRA_FEATURES, "opened_members": opened_members, "test_members_opened": False, "cohort_changed": False, "models_fitted": False, "implementation_sha256": _sha(Path(__file__)), "extended_features_sha256": _sha(stage / "extended_features.csv")})
        stage.rename(output)
        return output
    except Exception:
        shutil.rmtree(stage)
        raise
