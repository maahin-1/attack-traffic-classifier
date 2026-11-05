"""Rebuild research reports from checked saved scores without loading models."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import shutil
import tempfile
from collections import Counter, defaultdict
from datetime import date, datetime, timezone
from pathlib import Path

from .audit import _validate
from .evaluate import binary_metrics


_MODELS = {"baseline", "random_forest"}
_PREDICTION_FIELDS = {"variant", "model_id", "model", "record_id", "partition", "source_label", "family", "binary_label", "attack_score", "threshold", "prediction", "class_prediction", "event_start"}
_TIME_FIELDS = {"capture_date", "source_timestamp", "local_start_lower", "local_start_upper", "local_end_upper", "origin_member", "origin_record", "timing_status"}
_CLASS_FIELDS = ["variant", "model", "family", "training_support", "test_support", "seen_in_training", "binary_detection_recall", "family_attribution_recall"]
_METRIC_FIELDS = ["variant", "model", "partition", "model_id", "threshold", "feasible", "fpr", "recall", "precision", "pr_auc", "precision_at_k", "k", "alert_count", "benign_support", "attack_support", "total_support", "tp", "fp", "tn", "fn", "fpr_lower_95", "fpr_upper_95", "recall_lower_95", "recall_upper_95"]
_COMPARISON_FIELDS = ["reference_variant", "variant", "model", "metric", "reference_value", "value", "delta", "scope"]
_SOURCE_FILES = ["manifest.json", "config.json", "metrics.json", "predictions.csv", "per_class.csv", "audit/manifest.json", "audit/splits.csv", "audit/quality.json", "audit/inventory.json"]


def _fail(message):
    raise ValueError(f"Saved run validation failed: {message}")


def _json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), parse_constant=lambda value: _fail(f"nonfinite JSON constant {value} in {path.name}"))
    except (OSError, json.JSONDecodeError) as exc:
        _fail(f"cannot read required artifact {path}: {exc}")
    if not isinstance(value, dict):
        _fail(f"{path.name} must contain an object")
    return value


def _csv(path: Path, required: set[str], *, exact=False, optional=()):
    try:
        with path.open(newline="", encoding="utf-8-sig") as stream:
            reader = csv.DictReader(stream)
            headers = reader.fieldnames or []
            if len(headers) != len(set(headers)) or not required.issubset(headers) or (exact and not set(headers).issubset(required | set(optional))):
                _fail(f"unexpected CSV schema in {path.name}")
            for row in reader:
                if None in row or any(value is None for value in row.values()):
                    _fail(f"malformed CSV record in {path.name}")
                yield row
    except OSError as exc:
        _fail(f"cannot read required artifact {path}: {exc}")


def _number(value, field, *, optional=False):
    if optional and value == "":
        return None
    if isinstance(value, bool):
        _fail(f"{field} must be numeric")
    try:
        number = float(value)
    except (TypeError, ValueError):
        _fail(f"{field} must be numeric")
    if not math.isfinite(number):
        _fail(f"{field} must be finite")
    return number


def _integer(value, field):
    number = _number(value, field)
    if number < 0 or int(number) != number:
        _fail(f"{field} must be a nonnegative integer")
    return int(number)


def _time(value, field):
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            _fail(f"{field} lacks a timezone")
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        _fail(f"{field} must be an aware ISO timestamp")


def _date(value, field):
    try:
        parsed = date.fromisoformat(value)
        if parsed.isoformat() != value:
            _fail(f"{field} must be a YYYY-MM-DD capture date")
        return parsed
    except (TypeError, ValueError):
        _fail(f"{field} must be a YYYY-MM-DD capture date")


def _local_time(value, field):
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is not None or "T" not in value:
            _fail(f"{field} must be a naive local ISO datetime, not a UTC instant")
        return parsed
    except (TypeError, ValueError):
        _fail(f"{field} must be a naive local ISO datetime")


def _date_partition(day, validation, test):
    return "train" if day < validation else "validation" if day < test else "test"


def _capture_partition(row, dataset, config, validation, test):
    """Check day partitions without turning ambiguous local clocks into UTC."""
    day = _date(row.get("capture_date"), "capture_date")
    partition = _date_partition(day, validation, test)
    if not row.get("timing_status"):
        _fail("capture-date rows require an explicit timing_status")
    unresolved = dataset.get("timezone", config.get("timezone")) == "unresolved"
    if unresolved and (row["event_start"] or row["event_end"]):
        _fail("unresolved source clocks cannot claim UTC event timestamps")
    if not unresolved and not row["event_start"]:
        _fail("resolved source clocks require a measured event start")
    if row["event_start"]:
        start = _time(row["event_start"], "retained event_start")
        if start.date() != day:
            _fail("known event start differs from capture_date")
        if row["event_end"]:
            end = _time(row["event_end"], "retained event_end")
            if end < start or _date_partition(end.date(), validation, test) != partition:
                _fail("known event interval crosses a capture-date partition boundary")
    else:
        if row["event_end"] or not row.get("source_timestamp"):
            _fail("ambiguous clocks require the source timestamp and no claimed event end")
        lower = _local_time(row.get("local_start_lower"), "local_start_lower")
        upper = _local_time(row.get("local_start_upper"), "local_start_upper")
        end_upper = _local_time(row.get("local_end_upper"), "local_end_upper")
        if not lower <= upper <= end_upper or not lower.date() <= day <= upper.date():
            _fail("inconsistent local start/end uncertainty interval")
        if any(_date_partition(bound.date(), validation, test) != partition for bound in (lower, upper, end_upper)):
            _fail("possible local interval crosses a capture-date partition boundary")
    return partition


def _equal(actual, expected, where):
    """Exact structure/integer checks, documented 1e-12 numeric tolerance."""
    if isinstance(expected, dict):
        if not isinstance(actual, dict) or set(actual) != set(expected):
            _fail(f"inconsistent fields at {where}")
        for key in expected:
            _equal(actual[key], expected[key], f"{where}.{key}")
    elif isinstance(expected, list):
        if not isinstance(actual, list) or len(actual) != len(expected):
            _fail(f"inconsistent list at {where}")
        for index, value in enumerate(expected):
            _equal(actual[index], value, f"{where}[{index}]")
    elif isinstance(expected, float):
        number = _number(actual, where)
        if not math.isclose(number, expected, rel_tol=1e-12, abs_tol=1e-12):
            _fail(f"inconsistent metric at {where}")
    elif actual != expected or (isinstance(expected, bool) and type(actual) is not bool):
        _fail(f"inconsistent value at {where}")


def _write_csv(path: Path, fields, rows):
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _hash(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def _verify(source: Path):
    manifest = _json(source / "manifest.json")
    config = _json(source / "config.json")
    _validate(config)
    notes = config.get("experiment_notes", [])
    if not isinstance(notes, list) or any(not isinstance(note, str) or not note.strip() for note in notes):
        _fail("experiment_notes must be a list of nonempty strings")
    saved_metrics = _json(source / "metrics.json")
    audit_manifest = _json(source / "audit/manifest.json")
    quality = _json(source / "audit/quality.json")
    inventory = _json(source / "audit/inventory.json")
    if manifest.get("schema_version") != 1 or manifest.get("stage") != "baseline_experiment" or config.get("version") != 1 or audit_manifest.get("schema_version") != 1 or audit_manifest.get("stage") != "data_audit_only":
        _fail("unsupported manifest/config schema or experiment stage")
    datasets = config.get("datasets")
    if not isinstance(datasets, list) or not datasets or any(not isinstance(item, dict) or not isinstance(item.get("variant"), str) for item in datasets):
        _fail("config must name datasets")
    variants = [item["variant"] for item in datasets]
    if len(set(variants)) != len(variants):
        _fail("each variant must have exactly one dataset release")
    by_variant = {item["variant"]: item for item in datasets}
    features = config.get("feature_allowlist")
    boundaries = config.get("boundaries")
    training = manifest.get("training")
    if not isinstance(features, list) or not features or not isinstance(boundaries, dict) or not isinstance(training, dict):
        _fail("missing feature, training or temporal control declarations")
    _equal(manifest.get("feature_allowlist"), features, "manifest.feature_allowlist")
    _equal(manifest.get("profile"), config.get("profile", "synthetic"), "manifest.profile")
    if manifest.get("profile") not in ("synthetic", "subset", "full"):
        _fail("unknown experiment profile")
    _equal(manifest.get("boundaries"), boundaries, "manifest.boundaries")
    _equal(audit_manifest.get("boundaries"), boundaries, "audit.boundaries")
    temporal_basis = config.get("temporal_basis", "event_time")
    if temporal_basis not in ("event_time", "capture_date"):
        _fail("unknown temporal_basis")
    _equal(manifest.get("temporal_basis", "event_time"), temporal_basis, "manifest.temporal_basis")
    _equal(audit_manifest.get("temporal_basis", "event_time"), temporal_basis, "audit.temporal_basis")
    if not isinstance(config.get("training", {}), dict):
        _fail("config training must be an object")
    for key, value in config.get("training", {}).items():
        _equal(training.get(key), value, f"training.{key}")
    budget = _integer(training.get("alert_budget"), "training.alert_budget")
    target = _number(training.get("fpr_target"), "training.fpr_target")
    if budget <= 0 or not 0 <= target <= 1:
        _fail("invalid alert budget or FPR target")
    parse_boundary = _date if temporal_basis == "capture_date" else _time
    validation_start = parse_boundary(boundaries.get("validation_start"), "validation_start")
    test_start = parse_boundary(boundaries.get("test_start"), "test_start")
    if validation_start >= test_start:
        _fail("temporal boundaries are out of order")
    if manifest.get("config_sha256") is not None:
        canonical = hashlib.sha256(json.dumps(config, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        _equal(manifest["config_sha256"], canonical, "config_sha256")
    if set(saved_metrics) != set(variants) or set(quality) != set(variants) or set(inventory) != set(variants):
        _fail("variant populations differ across saved artifacts")
    for document, field in ((manifest, "manifest"), (audit_manifest, "audit manifest")):
        populations = document.get("datasets")
        if not isinstance(populations, list) or any(not isinstance(item, dict) or not isinstance(item.get("variant"), str) for item in populations) or len(populations) != len(variants):
            _fail(f"{field} dataset declarations are incomplete")
        declared = {item.get("variant"): item for item in populations}
        if set(declared) != set(variants):
            _fail(f"{field} names unknown or duplicate variants")
        for variant in variants:
            for key in ("release", "source_url", "retrieved_at", "license"):
                _equal(declared[variant].get(key), by_variant[variant].get(key), f"{field}.{variant}.{key}")
            for key in ("timestamp_format", "timezone", "label_map_version"):
                _equal(declared[variant].get(key), by_variant[variant].get(key, config.get(key)), f"{field}.{variant}.{key}")
            if "preparation" in by_variant[variant]:
                if not isinstance(by_variant[variant]["preparation"], dict):
                    _fail("dataset preparation must be a saved metadata object")
                _equal(declared[variant].get("preparation"), by_variant[variant]["preparation"], f"{field}.{variant}.preparation")
    _equal(manifest["datasets"], audit_manifest["datasets"], "root/audit populations")
    _equal(audit_manifest.get("label_map_version"), config.get("label_map_version"), "audit.label_map_version")
    populations = {item["variant"]: item for item in manifest["datasets"]}

    records = {variant: {} for variant in variants}
    observed_quality = {variant: {"input_rows": 0, "dispositions": Counter(), "by_source_label": defaultdict(Counter)} for variant in variants}
    families = {variant: {part: Counter() for part in ("train", "validation", "test")} for variant in variants}
    binary_support = {variant: {part: Counter() for part in ("train", "validation", "test")} for variant in variants}
    required_splits = {"variant", "record_id", "source_file_index", "source_record", "event_start", "event_end", "source_label", "binary_label", "family", "partition", "disposition", "reason", "duplicate_group_id"}
    all_identifiers = set()
    retained_digests = {variant: set() for variant in variants}
    retained_labels = {variant: {} for variant in variants}
    duplicate_conflicts = {variant: Counter() for variant in variants}
    for row in _csv(source / "audit/splits.csv", required_splits, exact=True, optional={"attempted_category"} | _TIME_FIELDS):
        variant = row["variant"]
        if variant not in records or not row["record_id"] or row["record_id"] in all_identifiers:
            _fail("unknown variant or missing/duplicate split record ID")
        all_identifiers.add(row["record_id"])
        dataset = by_variant[variant]
        if temporal_basis == "capture_date" and dataset.get("timezone", config.get("timezone")) == "unresolved" and (row["event_start"] or row["event_end"]):
            _fail("unresolved source clocks cannot claim UTC event timestamps")
        mapping = dataset.get("label_map", config.get("label_map"))
        if not isinstance(mapping, dict) or row["source_label"] not in mapping:
            _fail("split has an unknown source label")
        label = _integer(row["binary_label"], "split binary_label")
        mapped = mapping[row["source_label"]]
        if not isinstance(mapped, dict) or label != mapped.get("binary") or row["family"] != mapped.get("family"):
            _fail("split binary/family metadata differs from versioned label mapping")
        disposition = row["disposition"]
        if disposition not in ("retained", "excluded", "quarantined"):
            _fail("unknown split disposition")
        count = observed_quality[variant]
        count["input_rows"] += 1
        count["dispositions"][disposition] += 1
        count["by_source_label"][row["source_label"]][disposition] += 1
        if disposition == "quarantined" and row["reason"] == "later_duplicate":
            previous = retained_labels[variant].get(row["duplicate_group_id"])
            if previous is None:
                _fail("later duplicate lacks an earlier retained group representative")
            duplicate_conflicts[variant]["duplicate_conflicting_source_label_rows"] += int(previous[0] != row["source_label"])
            duplicate_conflicts[variant]["duplicate_conflicting_binary_label_rows"] += int(previous[1] != label)
        if disposition != "retained":
            continue
        if temporal_basis == "capture_date":
            partition = _capture_partition(row, dataset, config, validation_start, test_start)
        else:
            start = _time(row["event_start"], "retained event_start")
            partition = "train" if start < validation_start else "validation" if start < test_start else "test"
        if row["partition"] != partition or row["reason"]:
            _fail("retained row has inconsistent partition or exclusion reason")
        if temporal_basis == "event_time" and row["event_end"]:
            end = _time(row["event_end"], "retained event_end")
            if end < start or any(start < cutoff <= end for cutoff in (validation_start, test_start)):
                _fail("retained row has invalid duration or crosses a partition boundary")
        if not row["duplicate_group_id"] or row["duplicate_group_id"] in retained_digests[variant]:
            _fail("retained duplicate group is missing or crosses records")
        retained_digests[variant].add(row["duplicate_group_id"])
        retained_labels[variant][row["duplicate_group_id"]] = (row["source_label"], label)
        records[variant][row["record_id"]] = row
        families[variant][partition][row["family"]] += 1
        binary_support[variant][partition][str(label)] += 1
    for variant in variants:
        count = observed_quality[variant]
        declared_quality = quality[variant]
        if not isinstance(declared_quality, dict):
            _fail("quality entry must be an object")
        _equal(declared_quality.get("input_rows"), count["input_rows"], f"quality.{variant}.input_rows")
        _equal(declared_quality.get("dispositions"), {key: count["dispositions"][key] for key in ("retained", "excluded", "quarantined")}, f"quality.{variant}.dispositions")
        _equal(declared_quality.get("by_source_label"), {key: dict(value) for key, value in count["by_source_label"].items()}, f"quality.{variant}.by_source_label")
        _equal(populations[variant].get("input_rows"), count["input_rows"], f"manifest.{variant}.input_rows")
        for field in ("duplicate_conflicting_source_label_rows", "duplicate_conflicting_binary_label_rows"):
            observed = duplicate_conflicts[variant][field]
            if field in declared_quality:
                _equal(declared_quality[field], observed, f"quality.{variant}.{field}")
            else:
                declared_quality[field] = observed  # Older runs did not save this derived count.
        prep = by_variant[variant].get("preparation")
        if prep is not None:
            selected = _integer(prep.get("selected_rows"), "preparation.selected_rows")
            _equal(selected, count["input_rows"], f"preparation.{variant}.selected_rows")
            members = prep.get("by_member")
            if not isinstance(members, dict) or any(not isinstance(value, dict) for value in members.values()):
                _fail("preparation requires per-member accounting")
            if "source_input_rows" in prep:
                totals = {key: _integer(prep.get(key), f"preparation.{key}") for key in ("source_input_rows", "source_flow_rows", "source_empty_excluded_rows", "selected_flow_rows", "unsampled_flow_rows", "selected_empty_rows", "unsampled_empty_rows")}
                _equal(totals["source_flow_rows"], totals["selected_flow_rows"] + totals["unsampled_flow_rows"], "preparation.flow_accounting")
                _equal(totals["source_input_rows"], totals["source_flow_rows"] + totals["source_empty_excluded_rows"], "preparation.source_accounting")
                _equal(totals["source_empty_excluded_rows"], totals["selected_empty_rows"] + totals["unsampled_empty_rows"], "preparation.empty_accounting")
                _equal(selected, totals["selected_flow_rows"], "preparation.selected_flow_rows")
                for key, total in totals.items():
                    _equal(sum(_integer(value.get(key), f"preparation.member.{key}") for value in members.values()), total, f"preparation.member_total.{key}")
            else:
                _equal(sum(_integer(value.get("selected_rows"), "preparation.member.selected_rows") for value in members.values()), selected, "preparation.member_total.selected_rows")
        coverage = inventory[variant]
        if not isinstance(coverage, dict):
            _fail("inventory entry must be an object")
        _equal(coverage.get("retained_family_support"), {key: dict(value) for key, value in families[variant].items()}, f"inventory.{variant}.retained_family_support")
        _equal(coverage.get("retained_binary_support"), {key: dict(value) for key, value in binary_support[variant].items()}, f"inventory.{variant}.retained_binary_support")
        for partition in ("train", "validation"):
            if not all(binary_support[variant][partition][label] for label in ("0", "1")):
                _fail("training/validation lacks required binary support")

    groups = defaultdict(dict)
    model_ids = set()
    for variant in variants:
        if not isinstance(saved_metrics[variant], dict) or set(saved_metrics[variant]) != _MODELS:
            _fail("each variant requires baseline and random_forest model records")
        for model, result in saved_metrics[variant].items():
            if not isinstance(result, dict) or not isinstance(result.get("model_id"), str) or not result["model_id"] or result["model_id"] in model_ids:
                _fail("missing/duplicate model identity")
            model_ids.add(result["model_id"])
            if not isinstance(result.get("threshold_policy"), dict):
                _fail("missing frozen threshold policy")
    for row in _csv(source / "predictions.csv", _PREDICTION_FIELDS, exact=True, optional=_TIME_FIELDS):
        variant, model, partition, identifier = (row[key] for key in ("variant", "model", "partition", "record_id"))
        if variant not in records or model not in _MODELS or partition not in ("validation", "test"):
            _fail("unknown prediction variant/model/partition")
        result = saved_metrics[variant][model]
        if row["model_id"] != result["model_id"]:
            _fail("prediction model ID differs from saved metrics")
        split = records[variant].get(identifier)
        if split is None or split["partition"] != partition:
            _fail("prediction ID/partition does not reference a retained audit row")
        for key in ("source_label", "family", "binary_label", "event_start"):
            if row[key] != split[key]:
                _fail(f"prediction {key} differs from audited metadata")
        for key in _TIME_FIELDS:
            if row.get(key, "") != split.get(key, ""):
                _fail(f"prediction {key} differs from audited timing metadata")
        group = groups[(variant, model, partition)]
        if identifier in group:
            _fail("duplicate prediction record ID within model/partition")
        score = _number(row["attack_score"], "attack_score")
        threshold = _number(row["threshold"], "prediction threshold")
        frozen = _number(result["threshold_policy"].get("threshold"), "frozen threshold")
        if threshold != frozen or not 0 <= score <= 1:
            _fail("prediction threshold differs from frozen policy or score is outside [0,1]")
        decision = _integer(row["prediction"], "prediction decision")
        if decision != int(score >= frozen):
            _fail("saved prediction decision differs from frozen threshold")
        if model == "random_forest" and row["class_prediction"] not in families[variant]["train"]:
            _fail("family prediction is outside trained family classes")
        if model == "baseline" and row["class_prediction"]:
            _fail("constant binary baseline cannot claim a family prediction")
        group[identifier] = dict(row, score=score, decision=decision, label=int(row["binary_label"]))

    recomputed = {}
    metric_rows, class_rows = [], []
    error_notes = []
    for variant in variants:
        recomputed[variant] = {}
        dataset = by_variant[variant]
        mapping = dataset.get("label_map", config.get("label_map", {}))
        family_names = sorted(set().union(*(set(values) for values in families[variant].values())) | {value["family"] for value in mapping.values()})
        for model in sorted(_MODELS):
            saved = saved_metrics[variant][model]
            policy = saved["threshold_policy"]
            frozen = _number(policy.get("threshold"), "frozen threshold")
            partition_metrics = {}
            for partition in ("validation", "test"):
                expected_ids = {identifier for identifier, row in records[variant].items() if row["partition"] == partition}
                scored = groups[(variant, model, partition)]
                if not expected_ids or set(scored) != expected_ids:
                    _fail("missing or extra saved score rows for a model/partition")
                ordered = list(scored.values())
                measured = binary_metrics([row["label"] for row in ordered], [row["score"] for row in ordered], frozen, list(scored), budget)
                if partition == "test":
                    unseen = [row for row in ordered if row["label"] == 1 and row["family"] not in families[variant]["train"]]
                    measured["unseen_attack_support"] = len(unseen)
                    measured["unseen_attack_recall"] = sum(row["decision"] for row in unseen) / len(unseen) if unseen else None
                stored = policy.get("validation_metrics") if partition == "validation" else saved.get("test")
                if not isinstance(stored, dict) or stored.get("threshold") != frozen:
                    _fail("saved partition metric threshold differs exactly from the frozen policy")
                _equal(stored, measured, f"metrics.{variant}.{model}.{partition}")
                partition_metrics[partition] = measured
                interval_fpr, interval_recall = measured["fpr_interval_95"], measured["recall_interval_95"]
                metric_rows.append({"variant": variant, "model": model, "partition": partition, "model_id": saved["model_id"], "threshold": frozen, "feasible": policy.get("feasible"), **{key: measured[key] for key in ("fpr", "recall", "precision", "pr_auc", "precision_at_k", "k", "alert_count")}, "benign_support": measured["support"]["benign"], "attack_support": measured["support"]["attack"], "total_support": measured["support"]["total"], **measured["confusion"], "fpr_lower_95": interval_fpr[0] if interval_fpr else None, "fpr_upper_95": interval_fpr[1] if interval_fpr else None, "recall_lower_95": interval_recall[0] if interval_recall else None, "recall_upper_95": interval_recall[1] if interval_recall else None})
            val = partition_metrics["validation"]
            useful = val["confusion"]["tp"] > 0
            expected_policy = {"threshold": frozen, "feasible": useful, "useful": useful, "fpr_constraint_satisfied": val["fpr"] <= target, "fpr_target": target, "status": "useful_operating_point" if useful else "infeasible_useful_detection", "validation_metrics": val}
            _equal(policy, expected_policy, f"threshold_policy.{variant}.{model}")
            if not expected_policy["fpr_constraint_satisfied"]:
                _fail("frozen operating point violates the declared validation FPR ceiling")
            recomputed[variant][model] = {"model_id": saved["model_id"], "threshold_policy": expected_policy, "test": partition_metrics["test"]}
            detected = {}
            for family in family_names:
                training_support = families[variant]["train"][family]
                rows = [row for row in groups[(variant, model, "test")].values() if row["family"] == family]
                labels = {value["binary"] for value in mapping.values() if value["family"] == family} | {row["label"] for row in rows}
                if len(labels) != 1:
                    _fail("family mixes benign and attack labels")
                attack = 1 in labels
                hits = sum(row["decision"] for row in rows)
                detection = hits / len(rows) if rows and attack else None
                attribution = sum(row["class_prediction"] == family for row in rows) / len(rows) if rows and model == "random_forest" else None
                class_rows.append({"variant": variant, "model": model, "family": family, "training_support": training_support, "test_support": len(rows), "seen_in_training": bool(training_support), "binary_detection_recall": detection, "family_attribution_recall": attribution})
                if attack and rows:
                    detected[family] = (hits, len(rows), detection)
            if model == "random_forest":
                if detected:
                    dominant = max(detected, key=lambda family: (detected[family][0], family))
                    worst = min(detected, key=lambda family: (detected[family][2], family))
                    weak = min(detected, key=lambda family: (detected[family][1], family))
                    hits, total, _ = detected[dominant]
                    total_hits = sum(value[0] for value in detected.values())
                    dominance = f"dominant detected family is {dominant} ({hits}/{total} detected; {hits}/{total_hits} of all attack true positives)" if total_hits else "no attack true positives were observed, so dominant detected family is undefined"
                    error_notes.append(f"{variant}: {dominance}. Lowest observed attack-family detection recall is {worst} ({detected[worst][2]:.6g}). Weakest present attack-family test support is {weak} ({detected[weak][1]} rows). These slices describe errors; no thresholds are retuned.")
                else:
                    error_notes.append(f"{variant}: test has no supported attack families; attack recall and dominant detected family are undefined.")
    expected_classes = {(row["variant"], row["model"], row["family"]): row for row in class_rows}
    observed_classes = set()
    for row in _csv(source / "per_class.csv", set(_CLASS_FIELDS), exact=True):
        key = (row["variant"], row["model"], row["family"])
        if key not in expected_classes or key in observed_classes:
            _fail("unknown/duplicate per-class record")
        observed_classes.add(key)
        expected = expected_classes[key]
        converted = {key: row[key] for key in ("variant", "model", "family")}
        for field in ("training_support", "test_support"):
            converted[field] = _integer(row[field], field)
        if row["seen_in_training"] not in ("True", "False"):
            _fail("seen_in_training must be True or False")
        converted["seen_in_training"] = row["seen_in_training"] == "True"
        for field in ("binary_detection_recall", "family_attribution_recall"):
            converted[field] = _number(row[field], field, optional=True)
        _equal(converted, expected, f"per_class.{key}")
    if observed_classes != set(expected_classes):
        _fail("per-class artifact is missing rows")
    return manifest, config, quality, recomputed, metric_rows, class_rows, error_notes


def _md(value):
    if value is None:
        return "null"
    if isinstance(value, float):
        return f"{value:.6g}"
    return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def rebuild_report(run_dir: str | Path, output_dir: str | Path, *, charts=False, parquet=False) -> Path:
    """Verify saved scores and publish a fresh report without fitting or unpickling.

    The source run is immutable. No threshold selection is called; saved frozen
    thresholds are used exactly. Recomputed metric floats allow a 1e-12 tolerance.
    """
    source = Path(run_dir).resolve()
    output = Path(output_dir).resolve()
    if not source.is_dir():
        raise ValueError(f"Saved run does not exist: {source}")
    if output.exists() or output.is_relative_to(source):
        raise ValueError("Report output must be a new directory outside the immutable source run")
    source_hashes = {relative: _hash(source / relative) for relative in _SOURCE_FILES if (source / relative).is_file()}
    manifest, config, quality, metrics, metric_rows, class_rows, error_notes = _verify(source)
    if len(source_hashes) != len(_SOURCE_FILES):
        _fail("required source artifacts are incomplete")
    variants = [dataset["variant"] for dataset in config["datasets"]]
    comparisons = []
    if len(variants) >= 2:
        reference = variants[0]
        for variant in variants[1:]:
            for model in sorted(_MODELS):
                for metric in ("fpr", "recall", "precision", "pr_auc", "precision_at_k"):
                    before = metrics[reference][model]["test"][metric]
                    after = metrics[variant][model]["test"][metric]
                    comparisons.append({"reference_variant": reference, "variant": variant, "model": model, "metric": metric, "reference_value": before, "value": after, "delta": after - before if before is not None and after is not None else None, "scope": "pipeline/data-version population comparison; not label-only causal analysis"})
    temporal_basis = config.get("temporal_basis", "event_time")
    controls = {"feature_allowlist": manifest["feature_allowlist"], "training": manifest["training"], "boundaries": manifest["boundaries"], "temporal_basis": temporal_basis, "comparison_eligible": bool(comparisons)}
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".report-", dir=output.parent))
    try:
        _write_csv(stage / "metrics.csv", _METRIC_FIELDS, metric_rows)
        _write_csv(stage / "per_class.csv", _CLASS_FIELDS, class_rows)
        (stage / "metrics.json").write_text(json.dumps(metrics, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
        if comparisons:
            _write_csv(stage / "comparison.csv", _COMPARISON_FIELDS, comparisons)
        optional_outputs = []
        if charts:
            try:
                from .plots import write_charts
                optional_outputs.extend(write_charts(stage))
            except ImportError as exc:
                raise ValueError("Report charts require the optional plotting dependencies") from exc
        if parquet:
            try:
                from .exports import export_parquet
                optional_outputs.extend(export_parquet(source, stage))
            except ImportError as exc:
                raise ValueError("Parquet export requires the optional pyarrow dependency") from exc
        lines = ["# Verified saved-score report", "", "Rebuilt from saved validation/test scores without retraining, loading serialized models, selecting new thresholds or modifying the source run.", "", f"Profile: {_md(manifest.get('profile'))}. All original frozen thresholds are preserved exactly.", ""]
        if comparisons:
            boundary_description = "capture-day partitions" if temporal_basis == "capture_date" else "UTC time boundaries"
            lines.extend([f"This is a controlled pipeline/data-version population comparison using the same feature policy, declared model settings and {boundary_description}. Population and label differences remain visible. It is not label-only causal analysis; regenerated flows need not match one-to-one.", ""])
        else:
            lines.extend([f"Single-variant run: only {_md(variants[0])} is available. Original-versus-corrected comparison is unavailable. No comparison result or dataset-correction benefit is claimed.", ""])
        if temporal_basis == "capture_date":
            lines.extend(["Temporal basis: capture_date. Training uses earlier capture days, validation the next configured days, and testing later days. Unknown original AM/PM, timezone and source precision remain unresolved; blank UTC event fields are intentional. Local uncertainty intervals are checked for possible partition-boundary overlap. These controls establish day chronology, not identical recovered UTC event instants or intraday order. Duplicate retention follows earliest capture date with deterministic source order within a day, not verified event order. Source timestamps, capture dates and uncertainty metadata remain in the source audit and predictions; no date surrogate is presented as a measured event timestamp.", ""])
        if manifest.get("profile") == "synthetic":
            lines.extend(["Synthetic fixtures verify software behavior only; these scores do not demonstrate intrusion-detection effectiveness.", ""])
        elif manifest.get("profile") == "subset":
            lines.extend(["A deterministic subset describes its sampled population and is not a full-release benchmark. These captures do not establish enterprise-network performance.", ""])
        else:
            lines.extend(["The full profile describes the configured local release population. The full-profile name does not establish completeness of external acquisition or enterprise-network generalization; inspect release provenance and row counts.", ""])
        if config.get("experiment_notes"):
            lines.extend(["Experiment notes:", ""] + [f"- {_md(note)}" for note in config["experiment_notes"]] + [""])
        preparations = [(dataset["variant"], dataset["preparation"]) for dataset in config["datasets"] if "preparation" in dataset]
        if preparations:
            lines.extend(["Source preparation precedes the model audit. The following counts come from saved preparation metadata; selected rows are checked against audit input totals. Raw archives are not reread during reconstruction.", "", "| Variant | Source CSV records | Source padding excluded | Nonempty source flows | Selected flows sent to audit | Unselected flows | Selected padding excluded before audit |", "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"])
            for variant, prep in preparations:
                source_total = prep.get("source_input_rows")
                if source_total is None:
                    source_total = sum(_integer(value.get("source_rows"), "preparation.member.source_rows") for value in prep["by_member"].values())
                values = (variant, source_total, prep.get("source_empty_excluded_rows"), prep.get("source_flow_rows"), prep["selected_rows"], prep.get("unsampled_flow_rows"), prep.get("selected_empty_rows"))
                lines.append("| " + " | ".join(_md(value) for value in values) + " |")
            lines.extend(["", "Null source-preparation counts were not separately recorded and must not be inferred as zero. Original all-85-fields-empty records are excluded source padding with missing labels; their source ordinals and sample-selection flags are retained in the preparation exclusions artifact. They are not silently labeled benign or included in model-flow support. Unselected flows describe subset selection, separately from source-padding exclusions and downstream quality exclusions.", ""])
        lines.extend(["| Variant | Release | Input rows | Retained | Excluded | Quarantined |", "| --- | --- | ---: | ---: | ---: | ---: |"])
        for dataset in manifest["datasets"]:
            audit = quality[dataset["variant"]]
            dispositions = audit["dispositions"]
            lines.append("| " + " | ".join(_md(value) for value in (dataset["variant"], dataset["release"], audit["input_rows"], dispositions["retained"], dispositions["excluded"], dispositions["quarantined"])) + " |")
        lines.extend(["", "Every selected input flow is accounted for in the source audit. Preparation exclusions and unselected source rows are disclosed separately above when recorded. Losses change the retained population and must be considered alongside model scores.", "", "| Variant | Later duplicates with different source label | Later duplicates with different binary label |", "| --- | ---: | ---: |"])
        for variant in variants:
            lines.append("| " + " | ".join(_md(value) for value in (variant, quality[variant]["duplicate_conflicting_source_label_rows"], quality[variant]["duplicate_conflicting_binary_label_rows"])) + " |")
        lines.extend(["", "Conflict counts compare each quarantined later duplicate with its retained representative. They expose labeling ambiguity and do not adjudicate which label is correct.", "", "| Variant | Model | Partition | Frozen threshold | Useful validation point | FPR | Recall | Precision | Precision@K | K | Benign support | Attack support |", "| --- | --- | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"])
        for row in metric_rows:
            fields = ("variant", "model", "partition", "threshold", "feasible", "fpr", "recall", "precision", "precision_at_k", "k", "benign_support", "attack_support")
            lines.append("| " + " | ".join(_md(row[field]) for field in fields) + " |")
        lines.extend(["", "Threshold precision is null when no alerts are emitted. Precision@K ranks the top min(alert budget, partition population) scores even when the frozen operating point emits no alerts; it is not the precision of emitted alerts. Ties use stable record IDs.", "", "| Variant | Model | Family | Training support | Test support | Seen in training | Binary attack detection recall | Family attribution recall |", "| --- | --- | --- | ---: | ---: | --- | ---: | ---: |"])
        for row in class_rows:
            lines.append("| " + " | ".join(_md(row[field]) for field in _CLASS_FIELDS) + " |")
        lines.extend(["", "Absent test classes have null recall; absent training families are unseen. A closed-set family model cannot learn an absent family, while binary detection can still flag its flows. Benign-family binary attack recall is undefined.", ""])
        lines.extend(_md(note) + "\n" for note in error_notes)
        lines.extend(["", "Source labels and the optional attempted-category field remain in the local audit; scored records retain source labels and mapped families. Inspect the versioned mapping before interpreting attempted/effective attack distinctions. Attempted Category, Effective Category, labels, identifiers, ports and timestamps are metadata, never numeric model features. Public reports omit endpoint IP/port values.", "", "FPR/recall intervals in metrics.json and metrics.csv are Wilson 95% flow-level intervals assuming independence. Temporal correlation is not modeled; no temporal-block comparison confidence claim is made. Small or weakly supported classes remain uncertain. Start-time coverage does not prove complete capture days; no measured daily false-alert capacity is inferred.", "", "Config, feature, model-setting and temporal controls were checked against the source manifest. Metric structures and supports were independently recomputed; numeric metric tolerance is 1e-12 and threshold consistency is exact. A consistent saved artifact set does not prove that the original data capture or labels were correct.", ""])
        if optional_outputs:
            lines.extend(["Additional artifacts:", ""] + [f"- [{_md(name)}]({name})" for name in optional_outputs] + [""])
        (stage / "report.md").write_text("\n".join(lines), encoding="utf-8")
        if any(_hash(source / relative) != expected for relative, expected in source_hashes.items()):
            _fail("source artifacts changed during report reconstruction")
        provenance = {"schema_version": 1, "source_run": str(source), "source_files": source_hashes, "controls": controls, "experiment_notes": config.get("experiment_notes", []), "metric_tolerance": 1e-12, "threshold_policy": "original thresholds preserved exactly; no selector or fitting invoked", "optional_outputs": optional_outputs}
        (stage / "provenance.json").write_text(json.dumps(provenance, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
        stage.rename(output)
        return output
    except Exception:
        shutil.rmtree(stage)
        raise
