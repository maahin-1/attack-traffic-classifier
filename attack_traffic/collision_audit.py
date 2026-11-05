"""Describe feature-projection collisions without changing cohorts or models."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import shutil
import tempfile
from collections import Counter, defaultdict
from pathlib import Path


_SOURCE_FILES = ("manifest.json", "config.json", "audit/manifest.json", "audit/quality.json", "audit/splits.csv", "audit/feature_list.json", "audit/retained_features.csv")
_GROUP_FIELDS = ["variant", "duplicate_group_id", "total_rows", "retained_rows", "later_duplicate_rows", "benign_rows", "attack_rows", "binary_conflict", "source_label_count", "source_label_conflict", "capture_date_count", "source_timestamp_count", "partition_count", "partition_support", "source_class_support", "family_support", "binary_minority_label_error_lower_bound", "duplicate_conflicting_binary_label_rows", "duplicate_conflicting_source_label_rows"]
_CLASS_FIELDS = ["variant", "source_label", "family", "binary_label", "input_rows", "retained_rows", "excluded_rows", "quarantined_rows", "later_duplicate_rows", "other_quarantine_rows", "loss_fraction", "reason_counts"]
_PARTITION_FIELDS = ["variant", "partition", "binary_label", "family", "input_rows", "retained_rows", "excluded_rows", "quarantined_rows", "later_duplicate_rows"]


def _read_json(path):
    try:
        value = json.loads(path.read_text(encoding="utf-8"), parse_constant=lambda value: _reject(f"nonfinite JSON constant in {path.name}"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read collision-audit source {path}: {exc}") from exc
    if not isinstance(value, dict):
        _reject(f"{path.name} must contain an object")
    return value


def _reject(message):
    raise ValueError(f"Collision-audit validation failed: {message}")


def _hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _rows(path, fields, *, exact=False):
    try:
        with path.open(newline="", encoding="utf-8-sig") as stream:
            reader = csv.DictReader(stream)
            headers = reader.fieldnames or []
            if len(headers) != len(set(headers)) or not set(fields).issubset(headers) or (exact and set(headers) != set(fields)):
                _reject(f"unexpected columns in {path.name}")
            for row in reader:
                if None in row or any(value is None for value in row.values()):
                    _reject(f"malformed CSV row in {path.name}")
                yield row
    except OSError as exc:
        raise ValueError(f"Cannot read collision-audit source {path}: {exc}") from exc


def _write_csv(path, fields, rows):
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _dump(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


def _md(value):
    return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def audit_collisions(run_dir: str | Path, output_dir: str | Path) -> Path:
    """Publish an immutable diagnostic audit of an existing saved cohort.

    All partitions may be inspected descriptively. This function never reads
    predictions, models or raw endpoint identities; it neither changes quarantine
    nor selects features, model settings, thresholds, or an experiment winner.
    """
    source, output = Path(run_dir).resolve(), Path(output_dir).resolve()
    if not source.is_dir():
        raise ValueError(f"Collision-audit source run does not exist: {source}")
    if output.exists() or output.is_relative_to(source):
        raise ValueError("Collision-audit output must be a new directory outside its immutable source run")
    for relative in _SOURCE_FILES:
        if not (source / relative).is_file():
            _reject(f"missing required source artifact {relative}")
    source_hashes = {relative: _hash(source / relative) for relative in _SOURCE_FILES}
    manifest, config, audit_manifest, quality, feature_list = (_read_json(source / relative) for relative in ("manifest.json", "config.json", "audit/manifest.json", "audit/quality.json", "audit/feature_list.json"))
    if manifest.get("schema_version") != 1 or config.get("version") != 1 or audit_manifest.get("schema_version") != 1:
        _reject("unsupported manifest/config schema version")
    datasets = config.get("datasets")
    if not isinstance(datasets, list) or not datasets or any(not isinstance(dataset, dict) or not isinstance(dataset.get("variant"), str) for dataset in datasets):
        _reject("config must name dataset variants")
    variants = [dataset["variant"] for dataset in datasets]
    if len(set(variants)) != len(variants) or set(quality) != set(variants):
        _reject("unknown or duplicate variant declarations")
    datasets = {dataset["variant"]: dataset for dataset in datasets}
    features = config.get("feature_allowlist")
    if not isinstance(features, list) or not features or any(not isinstance(value, str) for value in features) or len(set(features)) != len(features):
        _reject("invalid numeric feature declaration")
    if manifest.get("feature_allowlist") != features or feature_list.get("features") != features or feature_list.get("units") != config.get("feature_units"):
        _reject("feature controls differ across manifest/config/feature list")
    if manifest.get("boundaries") != config.get("boundaries") or audit_manifest.get("boundaries") != config.get("boundaries"):
        _reject("temporal controls differ across source artifacts")
    for document in (manifest, audit_manifest):
        declared = document.get("datasets")
        if not isinstance(declared, list) or len(declared) != len(variants) or any(not isinstance(item, dict) or not isinstance(item.get("variant"), str) for item in declared):
            _reject("malformed dataset manifest")
        declared = {dataset["variant"]: dataset for dataset in declared}
        if set(declared) != set(variants):
            _reject("dataset manifest variants are inconsistent")
        for variant in variants:
            if declared[variant].get("release") != datasets[variant].get("release"):
                _reject("dataset release versions are inconsistent")
    groups = {variant: {} for variant in variants}
    classes = {variant: {} for variant in variants}
    partition_classes = defaultdict(Counter)
    totals = {variant: Counter() for variant in variants}
    reasons = {variant: Counter() for variant in variants}
    other_quarantine_reasons = {variant: Counter() for variant in variants}
    retained = {}
    all_ids = set()
    split_fields = ("variant", "record_id", "source_label", "family", "binary_label", "partition", "disposition", "reason", "duplicate_group_id")
    for row in _rows(source / "audit/splits.csv", split_fields):
        variant, identifier = row["variant"], row["record_id"]
        if variant not in totals or not identifier.strip() or identifier in all_ids:
            _reject("unknown variant or empty/duplicate source record ID")
        all_ids.add(identifier)
        disposition, reason, digest = row["disposition"], row["reason"], row["duplicate_group_id"]
        if disposition not in ("retained", "excluded", "quarantined") or row["partition"] not in ("train", "validation", "test", "unassigned"):
            _reject("unknown row disposition or partition")
        if disposition == "retained" and (reason or row["partition"] == "unassigned"):
            _reject("retained row has an exclusion reason or unassigned partition")
        if disposition != "retained" and not reason:
            _reject("excluded/quarantined row lacks a reason")
        if row["binary_label"] not in ("0", "1"):
            _reject("source binary label must be0or1")
        mapping = datasets[variant].get("label_map", config.get("label_map"))
        if not isinstance(mapping, dict) or row["source_label"] not in mapping:
            _reject("unmapped source label")
        mapped = mapping[row["source_label"]]
        if not isinstance(mapped, dict) or mapped.get("binary") != int(row["binary_label"]) or mapped.get("family") != row["family"]:
            _reject("saved binary/family labels differ from the declared mapping")
        label_class = classes[variant].setdefault(row["source_label"], {"family": row["family"], "binary_label": int(row["binary_label"]), "counts": Counter(), "reasons": Counter()})
        label_class["counts"][disposition] += 1
        totals[variant]["input_rows"] += 1
        totals[variant][disposition] += 1
        partition_key = (variant, row["partition"], int(row["binary_label"]), row["family"])
        partition_classes[partition_key][disposition] += 1
        if reason:
            reasons[variant][reason] += 1
            label_class["reasons"][reason] += 1
        eligible = disposition == "retained" or (disposition == "quarantined" and reason == "later_duplicate")
        if not eligible:
            if disposition == "quarantined":
                totals[variant]["nonduplicate_quarantine_rows"] += 1
                other_quarantine_reasons[variant][reason] += 1
            continue
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            _reject("eligible row lacks a canonical feature-group SHA-256")
        totals[variant]["eligible_rows"] += 1
        group = groups[variant].get(digest)
        if disposition == "retained":
            if group is not None:
                _reject("multiple retained representatives or duplicate preceding its representative")
            group = {"counts": Counter(), "binary": Counter(), "source": Counter(), "family": Counter(), "partition": Counter(), "dates": set(), "timestamps": set(), "representative_binary": row["binary_label"], "representative_source": row["source_label"]}
            groups[variant][digest] = group
            retained[(variant, identifier)] = digest
        elif group is None:
            _reject("later duplicate has no earlier retained representative")
        else:
            totals[variant]["later_duplicate_rows"] += 1
            label_class["counts"]["later_duplicate"] += 1
            partition_classes[partition_key]["later_duplicate"] += 1
            if row["binary_label"] != group["representative_binary"]:
                group["counts"]["conflicting_binary"] += 1
            if row["source_label"] != group["representative_source"]:
                group["counts"]["conflicting_source"] += 1
        group["counts"][disposition] += 1
        group["binary"][row["binary_label"]] += 1
        group["source"][row["source_label"]] += 1
        group["family"][row["family"]] += 1
        group["partition"][row["partition"]] += 1
        date = row.get("capture_date", "") or row.get("event_start", "")[:10]
        timestamp = row.get("source_timestamp", "") or row.get("event_start", "")
        if date:
            group["dates"].add(date)
        if timestamp:
            group["timestamps"].add(timestamp)

    observed_features = set()
    for row in _rows(source / "audit/retained_features.csv", ["variant", "record_id", *features], exact=True):
        key = (row["variant"], row["record_id"])
        if key not in retained or key in observed_features:
            _reject("retained feature IDs differ from the split audit")
        try:
            values = [float(row[feature]) for feature in features]
        except ValueError as exc:
            raise ValueError("Collision-audit retained feature must be numeric") from exc
        if not all(math.isfinite(value) for value in values):
            _reject("retained features contain nonfinite values")
        values = [0.0 if value == 0 else value for value in values]
        digest = hashlib.sha256(json.dumps(values, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
        if digest != retained[key]:
            _reject("retained numeric feature hash differs from the recorded duplicate group")
        observed_features.add(key)
    if observed_features != set(retained):
        _reject("retained feature artifact is missing records")

    group_rows, class_rows, partition_rows = [], [], []
    summary = {"schema_version": 1, "stage": "duplicate_projection_audit", "feature_allowlist": features, "feature_count": len(features), "eligible_population": "retained plus later_duplicate rows only; excluded numeric rows and other quarantine reasons remain separately counted", "bound_scope": "descriptive minimum errors for any deterministic binary assignment to identical configured feature vectors in the eligible selected pre-quarantine population; not an error estimate for the retained training/evaluation cohort", "separation_note": "All partitions are inspected diagnostically; these statistics do not alter quarantine, cohorts, grids, selected model settings, frozen thresholds or experiment winners", "variants": {}}
    for variant in variants:
        total = totals[variant]
        summary_variant = {key: total[key] for key in ("input_rows", "retained", "excluded", "quarantined", "eligible_rows", "later_duplicate_rows", "nonduplicate_quarantine_rows")}
        summary_variant.update(feature_group_count=len(groups[variant]), duplicate_group_count=0, binary_conflict_group_count=0, binary_conflict_group_rows=0, binary_minority_label_error_lower_bound=0, source_label_conflict_group_count=0, duplicate_conflicting_binary_label_rows=0, duplicate_conflicting_source_label_rows=0, cross_capture_date_group_count=0, differing_source_timestamp_group_count=0, binary_conflict_cross_capture_date_group_count=0, binary_conflict_differing_source_timestamp_group_count=0, nonduplicate_quarantine_reasons=dict(other_quarantine_reasons[variant]))
        for digest, group in sorted(groups[variant].items()):
            count = sum(group["binary"].values())
            conflict = len(group["binary"]) > 1
            bound = min(group["binary"].values()) if conflict else 0
            summary_variant["binary_minority_label_error_lower_bound"] += bound
            summary_variant["duplicate_conflicting_binary_label_rows"] += group["counts"]["conflicting_binary"]
            summary_variant["duplicate_conflicting_source_label_rows"] += group["counts"]["conflicting_source"]
            if count <= 1:
                continue
            summary_variant["duplicate_group_count"] += 1
            summary_variant["cross_capture_date_group_count"] += int(len(group["dates"]) > 1)
            summary_variant["differing_source_timestamp_group_count"] += int(len(group["timestamps"]) > 1)
            summary_variant["source_label_conflict_group_count"] += int(len(group["source"]) > 1)
            if conflict:
                summary_variant["binary_conflict_group_count"] += 1
                summary_variant["binary_conflict_group_rows"] += count
                summary_variant["binary_conflict_cross_capture_date_group_count"] += int(len(group["dates"]) > 1)
                summary_variant["binary_conflict_differing_source_timestamp_group_count"] += int(len(group["timestamps"]) > 1)
            group_rows.append({"variant": variant, "duplicate_group_id": digest, "total_rows": count, "retained_rows": group["counts"]["retained"], "later_duplicate_rows": group["counts"]["quarantined"], "benign_rows": group["binary"]["0"], "attack_rows": group["binary"]["1"], "binary_conflict": conflict, "source_label_count": len(group["source"]), "source_label_conflict": len(group["source"]) > 1, "capture_date_count": len(group["dates"]), "source_timestamp_count": len(group["timestamps"]), "partition_count": len(group["partition"]), "partition_support": json.dumps(group["partition"], sort_keys=True), "source_class_support": json.dumps(group["source"], sort_keys=True), "family_support": json.dumps(group["family"], sort_keys=True), "binary_minority_label_error_lower_bound": bound, "duplicate_conflicting_binary_label_rows": group["counts"]["conflicting_binary"], "duplicate_conflicting_source_label_rows": group["counts"]["conflicting_source"]})
        declared_quality = quality[variant]
        if not isinstance(declared_quality, dict):
            _reject("quality entries must be objects")
        for key in ("input_rows", "duplicate_conflicting_binary_label_rows", "duplicate_conflicting_source_label_rows"):
            if declared_quality.get(key) != summary_variant[key]:
                _reject(f"saved quality {variant}.{key} differs from independent row accounting")
        if declared_quality.get("dispositions") != {key: total[key] for key in ("retained", "excluded", "quarantined")} or declared_quality.get("reasons") != dict(reasons[variant]):
            _reject("saved quality disposition/reason totals differ from split rows")
        observed_classes = {}
        for label, value in sorted(classes[variant].items()):
            counts = value["counts"]
            observed_classes[label] = {key: counts[key] for key in ("retained", "excluded", "quarantined") if counts[key]}
            input_rows = sum(counts[key] for key in ("retained", "excluded", "quarantined"))
            class_rows.append({"variant": variant, "source_label": label, "family": value["family"], "binary_label": value["binary_label"], "input_rows": input_rows, "retained_rows": counts["retained"], "excluded_rows": counts["excluded"], "quarantined_rows": counts["quarantined"], "later_duplicate_rows": counts["later_duplicate"], "other_quarantine_rows": counts["quarantined"] - counts["later_duplicate"], "loss_fraction": 1 - counts["retained"] / input_rows, "reason_counts": json.dumps(value["reasons"], sort_keys=True)})
        if declared_quality.get("by_source_label") != observed_classes:
            _reject("saved per-source-class quality counts differ from independent row accounting")
        for document in (manifest, audit_manifest):
            declared_variant = next(dataset for dataset in document["datasets"] if dataset["variant"] == variant)
            if declared_variant.get("input_rows") != total["input_rows"]:
                _reject("manifest source input counts differ from split rows")
        summary["variants"][variant] = summary_variant
    for (variant, partition, binary_label, family), counts in sorted(partition_classes.items()):
        partition_rows.append({"variant": variant, "partition": partition, "binary_label": binary_label, "family": family, "input_rows": sum(counts[key] for key in ("retained", "excluded", "quarantined")), "retained_rows": counts["retained"], "excluded_rows": counts["excluded"], "quarantined_rows": counts["quarantined"], "later_duplicate_rows": counts["later_duplicate"]})
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".collision-audit-", dir=output.parent))
    try:
        _write_csv(stage / "group_summary.csv", _GROUP_FIELDS, group_rows)
        _write_csv(stage / "class_losses.csv", _CLASS_FIELDS, class_rows)
        _write_csv(stage / "partition_support.csv", _PARTITION_FIELDS, partition_rows)
        _dump(stage / "summary.json", summary)
        lines = ["# Duplicate projection audit", "", "Diagnostic audit only: source cohorts, quarantine decisions, models and frozen thresholds remain unchanged. All partitions are inspected descriptively; these statistics do not change a tuning grid or select an experiment winner.", "", f"The configured projection contains {len(features)} numeric features. Equality of this projection is not proof of shared source-flow identity. Hashes are references to feature groups, not endpoint identities.", "", "Eligible groups contain retained representatives and later_duplicate rows. Numeric exclusions, possible boundary crossings and any other quarantine reason are separately accounted for and do not enter the representative-conflict comparison.", "", "| Variant | Eligible rows | Groups | Duplicate groups | Binary-conflicting groups | Rows in those groups | Binary minority-label bound | Conflicting later rows against retained representative |", "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
        for variant in variants:
            value = summary["variants"][variant]
            lines.append("| " + " | ".join(_md(item) for item in (variant, value["eligible_rows"], value["feature_group_count"], value["duplicate_group_count"], value["binary_conflict_group_count"], value["binary_conflict_group_rows"], value["binary_minority_label_error_lower_bound"], value["duplicate_conflicting_binary_label_rows"])) + " |")
        lines.extend(["", "The minority-label bound is the sum of min(benign count, attack count) in conflicting groups. It describes unavoidable disagreement for any deterministic label assignment restricted to these feature vectors and these pre-quarantine labels. It is not an error floor for the already pruned evaluation cohort, a proof that labels are wrong, or a forecast of achievable model improvement.", "", "Conflicting-group counts, minority-label counts and conflicting later-row counts are different quantities. The last column matches the existing first-retained-representative audit counter; it is not a majority-vote label decision.", "", "| Variant | Source class | Input | Retained | Excluded | Quarantined | Later duplicates | Loss fraction |", "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |"])
        for row in class_rows:
            lines.append("| " + " | ".join(_md(item) for item in (row["variant"], row["source_label"], row["input_rows"], row["retained_rows"], row["excluded_rows"], row["quarantined_rows"], row["later_duplicate_rows"], f"{row['loss_fraction']:.6%}")) + " |")
        lines.extend(["", "Rows removed from repeated feature patterns change both class composition and the estimand: unique-pattern evaluation differs from flow-population evaluation. Distinct source timestamps/capture dates show that some repeated projections recur across events; this audit does not inspect private flow identity or establish whether every repeated record is a genuinely distinct flow.", "", "Capture-day chronology does not resolve the original missing AM/PM/timezone. Within-day source order remains a deterministic tie policy, not a verified earliest-event order. New independent measurements may separate some projection collisions; transformations derived solely from the existing feature vector cannot separate exact ties.", "", "Any proposed deduplication or feature-policy change requires a separate, explicitly controlled experiment. This audit does not remove ambiguous held-out examples, relabel records, rebalance evaluation, fit a model, inspect saved scores, or assert an accuracy gain.", ""])
        (stage / "report.md").write_text("\n".join(lines), encoding="utf-8")
        if any(_hash(source / relative) != expected for relative, expected in source_hashes.items()):
            _reject("source artifacts changed during the diagnostic audit")
        _dump(stage / "provenance.json", {"schema_version": 1, "source_run": str(source), "source_files": source_hashes, "cohort_changed": False, "models_fitted": False, "scores_inspected": False, "renderer_sha256": _hash(Path(__file__))})
        stage.rename(output)
        return output
    except Exception:
        shutil.rmtree(stage)
        raise
