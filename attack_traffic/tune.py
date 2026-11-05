"""Validation-only class-weight ablation on frozen audited cohorts.

This module never reads source metrics.json or predictions.csv, never loads a
serialized model, and discards test rows before interpreting labels or features.
"""

from __future__ import annotations

from collections import Counter
import csv
import hashlib
import json
import math
from pathlib import Path
import shutil
import tempfile
import time

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline

from .audit import _dump, _validate
from .evaluate import attack_scores, binary_metrics, select_threshold
from .model import environment_versions
from .report import _capture_partition, _date, _time


CANDIDATES = [("unweighted", None), ("balanced", "balanced"), ("balanced_subsample", "balanced_subsample")]
SOURCE_FILES = ["config.json", "manifest.json", "audit/manifest.json", "audit/splits.csv", "audit/retained_features.csv"]
METRIC_FIELDS = ["candidate", "class_weight", "variant", "status", "error", "threshold", "feasible", "useful", "fpr", "recall", "precision", "pr_auc", "precision_at_k", "k", "tp", "fp", "tn", "fn", "benign_support", "attack_support", "zero_score_benign", "zero_score_attack", "training_benign", "training_attack", "recall_lower_95", "recall_upper_95", "fpr_lower_95", "fpr_upper_95", "wall_seconds"]
PREDICTION_FIELDS = ["variant", "candidate", "record_id", "partition", "source_label", "family", "binary_label", "attack_score", "threshold", "prediction"]
CLASS_FIELDS = ["candidate", "variant", "family", "binary_label", "training_support", "validation_support", "seen_in_training", "binary_detection_recall", "zero_score_support", "zero_score_fraction"]


def _json(path):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"Cannot read frozen artifact {path}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"Frozen artifact must contain an object: {path.name}")
    return value


def _sha(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def _hash_object(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _positive_int(value, name, *, zero=False):
    if type(value) is not int or value < (0 if zero else 1):
        raise ValueError(f"{name} must be a {'nonnegative' if zero else 'positive'} integer")
    return value


def _csv(path, required, *, exact=None):
    with path.open(newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        headers = reader.fieldnames or []
        if len(set(headers)) != len(headers) or not set(required).issubset(headers) or (exact is not None and headers != exact):
            raise ValueError(f"Unexpected frozen CSV schema: {path.name}")
        for row in reader:
            if None in row or any(value is None for value in row.values()):
                raise ValueError(f"Malformed frozen CSV row: {path.name}")
            yield row


def _load_cohorts(source, config, manifest):
    """Load only retained train/validation rows and their feature records."""
    training = manifest.get("training")
    if not isinstance(training, dict):
        raise ValueError("Frozen manifest must contain training settings")
    parameters = {key: _positive_int(training.get(key), key, zero=key == "seed") for key in ("n_estimators", "max_depth", "min_samples_leaf", "seed", "n_jobs", "max_rows_per_variant", "alert_budget")}
    if training.get("class_weight") is not None:
        raise ValueError("The frozen reference must be an unweighted random forest")
    target = training.get("fpr_target")
    if isinstance(target, bool) or not isinstance(target, (int, float)) or not math.isfinite(target) or not 0 <= target <= 1:
        raise ValueError("Frozen fpr_target must lie in [0,1]")
    parameters["fpr_target"] = float(target)
    supplied = config.get("training", {})
    if not isinstance(supplied, dict) or any(training.get(key) != value for key, value in supplied.items()):
        raise ValueError("Frozen training config and manifest disagree")
    if manifest.get("schema_version") != 1 or manifest.get("stage") != "baseline_experiment":
        raise ValueError("Expected a frozen schema-version-1 baseline experiment")
    features = config["feature_allowlist"]
    basis = config.get("temporal_basis", "event_time")
    if manifest.get("feature_allowlist") != features or manifest.get("boundaries") != config["boundaries"] or manifest.get("temporal_basis", "event_time") != basis:
        raise ValueError("Frozen feature or temporal controls disagree")
    if manifest.get("config_sha256") is not None and manifest["config_sha256"] != _hash_object(config):
        raise ValueError("Frozen config hash mismatch")
    audit_manifest = _json(source / "audit/manifest.json")
    if audit_manifest.get("schema_version") != 1 or audit_manifest.get("stage") != "data_audit_only" or audit_manifest.get("datasets") != manifest.get("datasets") or audit_manifest.get("boundaries") != config["boundaries"] or audit_manifest.get("temporal_basis", "event_time") != basis:
        raise ValueError("Frozen audit and experiment controls disagree")
    datasets = {dataset["variant"]: dataset for dataset in config["datasets"]}
    populations = {dataset["variant"]: dataset for dataset in manifest["datasets"]}
    if set(populations) != set(datasets):
        raise ValueError("Frozen dataset populations disagree")
    for variant, dataset in datasets.items():
        adapter = dict(config, datasets=[dataset])
        for key in ("label_map", "label_map_version", "timezone", "timestamp_format"):
            if key in dataset:
                adapter[key] = dataset[key]
        _validate(adapter)
        for key in ("release", "source_url", "retrieved_at", "license"):
            if dataset.get(key) != populations[variant].get(key):
                raise ValueError(f"Frozen dataset provenance disagrees for {variant}.{key}")
    parse = _date if basis == "capture_date" else _time
    validation = parse(config["boundaries"]["validation_start"], "validation_start")
    test = parse(config["boundaries"]["test_start"], "test_start")
    records = {variant: [] for variant in datasets}
    observed_ids, observed_groups = set(), {variant: set() for variant in datasets}
    fields = ["partition", "disposition", "variant", "record_id", "source_label", "family", "binary_label", "duplicate_group_id", "source_file_index", "source_record", "event_start", "event_end"]
    for row in _csv(source / "audit/splits.csv", fields):
        # This guard precedes variant/label/clock conversion or semantic checks.
        if row["partition"] == "test":
            continue
        if row["disposition"] != "retained":
            continue
        if row["partition"] not in ("train", "validation") or row["variant"] not in datasets:
            raise ValueError("Unknown retained training/validation partition or variant")
        variant = row["variant"]
        if len(records[variant]) >= parameters["max_rows_per_variant"]:
            raise ValueError(f"Training/validation cohort exceeds max_rows_per_variant for {variant}")
        identifier = row["record_id"]
        if not identifier or identifier in observed_ids:
            raise ValueError("Duplicate or empty training/validation record ID")
        observed_ids.add(identifier)
        group = row["duplicate_group_id"]
        if not group or group in observed_groups[variant]:
            raise ValueError("Duplicate or missing retained feature group")
        observed_groups[variant].add(group)
        dataset = datasets[variant]
        mapping = dataset.get("label_map", config["label_map"])
        if row["source_label"] not in mapping:
            raise ValueError("Unknown training/validation source label")
        mapped = mapping[row["source_label"]]
        if row["binary_label"] not in ("0", "1") or int(row["binary_label"]) != mapped["binary"] or row["family"] != mapped["family"]:
            raise ValueError("Training/validation label mapping mismatch")
        try:
            file_index, ordinal = int(row["source_file_index"]), int(row["source_record"])
            file_hash = populations[variant]["files"][file_index]["sha256"]
        except (ValueError, KeyError, IndexError, TypeError) as error:
            raise ValueError("Invalid frozen source reference") from error
        if file_index < 0 or ordinal < 2 or identifier != hashlib.sha256(f"{variant}:{file_index}:{file_hash}:{ordinal}".encode()).hexdigest():
            raise ValueError("Frozen record ID does not match its source reference")
        if basis == "capture_date":
            actual_partition = _capture_partition(row, dataset, config, validation, test)
        else:
            start = _time(row["event_start"], "event_start")
            actual_partition = "train" if start < validation else "validation" if start < test else "test"
            if row["event_end"]:
                end = _time(row["event_end"], "event_end")
                if end < start or any(start < boundary <= end for boundary in (validation, test)):
                    raise ValueError("Retained source interval spans a partition boundary")
        if actual_partition != row["partition"]:
            raise ValueError("Frozen row partition disagrees with temporal controls")
        records[variant].append(row)
    locations = {row["record_id"]: (variant, index) for variant, rows in records.items() for index, row in enumerate(rows)}
    matrices = {variant: np.empty((len(rows), len(features)), dtype=float) for variant, rows in records.items()}
    found = set()
    for row in _csv(source / "audit/retained_features.csv", ["variant", "record_id", *features], exact=["variant", "record_id", *features]):
        identifier = row["record_id"]
        # All other feature rows, including held-out test, are skipped BEFORE float conversion.
        if identifier not in locations:
            continue
        variant, index = locations[identifier]
        if row["variant"] != variant or identifier in found:
            raise ValueError("Duplicate/mismatched training/validation feature ID")
        try:
            values = [float(row[feature]) for feature in features]
        except ValueError as error:
            raise ValueError("Nonnumeric training/validation feature") from error
        if not all(math.isfinite(value) for value in values):
            raise ValueError("Nonfinite training/validation feature")
        values = [0.0 if value == 0 else value for value in values]
        feature_digest = hashlib.sha256(json.dumps(values, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
        if feature_digest != records[variant][index]["duplicate_group_id"]:
            raise ValueError("Frozen training/validation feature hash mismatch")
        matrices[variant][index] = values
        found.add(identifier)
    if found != set(locations):
        raise ValueError("Missing training/validation feature records")
    cohorts = {}
    for variant, rows in records.items():
        labels = np.asarray([int(row["binary_label"]) for row in rows])
        train = np.asarray([row["partition"] == "train" for row in rows], dtype=bool)
        valid = np.asarray([row["partition"] == "validation" for row in rows], dtype=bool)
        for name, mask in (("train", train), ("validation", valid)):
            if set(labels[mask]) != {0, 1}:
                raise ValueError(f"{variant} {name} requires both binary classes")
        for family in {row["family"] for row in rows}:
            if len({int(row["binary_label"]) for row in rows if row["family"] == family}) != 1:
                raise ValueError("Frozen family mixes binary labels")
        cohorts[variant] = {"records": rows, "matrix": matrices[variant], "labels": labels, "train": train, "validation": valid}
    return cohorts, parameters


def _select_candidate(candidates):
    """Apply the fixed joint validation rule, separately from promotion."""
    names = [name for name, _ in CANDIDATES]
    tolerance = 1e-12
    expected_variants = set(candidates["unweighted"]["variants"])
    for name in names:
        entry = candidates[name]
        variants = list(entry["variants"].values())
        same_variants = set(entry["variants"]) == expected_variants
        successful = bool(variants) and same_variants and all(result["status"] == "ok" for result in variants)
        entry["variant_set_matches_reference"] = same_variants
        entry["eligible"] = successful and all(result["validation"]["fpr"] <= result["threshold_policy"]["fpr_target"] for result in variants)
        entry["mean_validation_recall"] = float(np.mean([result["validation"]["recall"] for result in variants])) if successful else None
        entry["mean_validation_fpr"] = float(np.mean([result["validation"]["fpr"] for result in variants])) if successful else None
    eligible = [name for name in names if candidates[name]["eligible"]]
    best = min(eligible, key=lambda name: (-candidates[name]["mean_validation_recall"], candidates[name]["mean_validation_fpr"], names.index(name))) if eligible else None
    reference = candidates["unweighted"]
    promote = False
    reason = "No jointly FPR-eligible candidate; no promotion."
    if best is not None and reference["eligible"]:
        winner = candidates[best]
        improve = winner["mean_validation_recall"] > reference["mean_validation_recall"] + tolerance
        nonregression = all(winner["variants"][variant]["validation"]["recall"] >= result["validation"]["recall"] - tolerance for variant, result in reference["variants"].items())
        promote = improve and nonregression
        reason = "Strictly higher mean validation recall with no variant recall regression." if promote else "Retain unweighted: no strict mean recall improvement, or at least one variant recall regressed."
    elif best is not None:
        reason = "Unweighted reference failed or violates the FPR rule; improvement cannot be established."
    return {"reference_candidate": "unweighted", "best_candidate": best, "promoted_candidate": best if promote else "unweighted", "promotion_passed": promote, "promotion_tolerance": tolerance, "reason": reason, "candidate_order": names, "rule": "Maximize unweighted mean variant validation recall subject to each variant FPR<=target; ties lower mean FPR, then candidate order. Promote only mean recall improvement greater than 1e-12 and no variant recall regression beyond 1e-12. All-negative operating points remain eligible with useful=False.", "scope": "Validation-only; no test scoring, metrics, threshold selection or model loading."}


def run_weight_ablation(source_run: str | Path, output_dir: str | Path, *, charts=False) -> Path:
    """Publish all three class-weight candidates without accessing test outcomes."""
    started = time.perf_counter()
    source, output = Path(source_run).resolve(), Path(output_dir).resolve()
    if not source.is_dir() or output.exists() or output.is_relative_to(source):
        raise ValueError("Ablation requires an existing source run and a new output directory outside it")
    hashes = {name: _sha(source / name) for name in SOURCE_FILES}
    config, manifest = _json(source / "config.json"), _json(source / "manifest.json")
    _validate(config)
    cohorts, settings = _load_cohorts(source, config, manifest)
    features = config["feature_allowlist"]
    parameters = {key: settings[key] for key in ("n_estimators", "max_depth", "min_samples_leaf", "n_jobs")}
    parameters["random_state"] = settings["seed"]
    cohort_hashes = {}
    for variant, cohort in cohorts.items():
        cohort_hashes[variant] = {}
        for partition in ("train", "validation"):
            mask = cohort[partition]
            rows = [row for row, included in zip(cohort["records"], mask) if included]
            cohort_hashes[variant][partition] = {"rows": len(rows), "ordered_record_ids_sha256": _hash_object([row["record_id"] for row in rows]), "labels_and_families_sha256": _hash_object([(row["binary_label"], row["source_label"], row["family"]) for row in rows]), "feature_matrix_sha256": hashlib.sha256(np.ascontiguousarray(cohort["matrix"][mask], dtype="<f8").tobytes()).hexdigest()}
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".ablation-", dir=output.parent))
    try:
        candidates, metric_rows, prediction_rows, class_rows = {}, [], [], []
        for name, weight in CANDIDATES:
            entry = candidates[name] = {"class_weight": weight, "variants": {}}
            for variant, cohort in cohorts.items():
                begun = time.perf_counter()
                records, matrix, labels = (cohort[key] for key in ("records", "matrix", "labels"))
                train, valid = cohort["train"], cohort["validation"]
                training_support = {"benign": int(np.sum(labels[train] == 0)), "attack": int(np.sum(labels[train] == 1))}
                row = {"candidate": name, "class_weight": weight if weight is not None else "None", "variant": variant, "training_benign": training_support["benign"], "training_attack": training_support["attack"]}
                try:
                    candidate_predictions, candidate_classes = [], []
                    pipeline = Pipeline([("preprocessing", "passthrough"), ("classifier", RandomForestClassifier(**parameters, class_weight=weight))])
                    pipeline.fit(matrix[train], labels[train])
                    scores = attack_scores(pipeline, matrix[valid])
                    operating = select_threshold(labels[valid], scores, settings["fpr_target"])
                    threshold = operating["threshold"]
                    valid_records = [record for record, included in zip(records, valid) if included]
                    measured = binary_metrics(labels[valid], scores, threshold, [record["record_id"] for record in valid_records], settings["alert_budget"])
                    operating["validation_metrics"] = measured
                    measured = dict(measured, zero_score_benign=int(np.sum((scores == 0) & (labels[valid] == 0))), zero_score_attack=int(np.sum((scores == 0) & (labels[valid] == 1))))
                    entry["variants"][variant] = {"status": "ok", "threshold_policy": operating, "validation": measured, "training_support": training_support}
                    for record, score in zip(valid_records, scores):
                        candidate_predictions.append({"variant": variant, "candidate": name, "record_id": record["record_id"], "partition": "validation", "source_label": record["source_label"], "family": record["family"], "binary_label": int(record["binary_label"]), "attack_score": float(score), "threshold": threshold, "prediction": int(score >= threshold)})
                    families = sorted({record["family"] for record in records})
                    training_families = Counter(record["family"] for record, included in zip(records, train) if included)
                    for family in families:
                        positions = [index for index, record in enumerate(valid_records) if record["family"] == family]
                        binary = {int(record["binary_label"]) for record in records if record["family"] == family}
                        if len(binary) != 1:
                            raise ValueError("Family mixes binary labels")
                        role = next(iter(binary))
                        hits = sum(scores[index] >= threshold for index in positions)
                        zeros = sum(scores[index] == 0 for index in positions)
                        candidate_classes.append({"candidate": name, "variant": variant, "family": family, "binary_label": role, "training_support": training_families[family], "validation_support": len(positions), "seen_in_training": bool(training_families[family]), "binary_detection_recall": float(hits / len(positions)) if positions and role else None, "zero_score_support": int(zeros), "zero_score_fraction": float(zeros / len(positions)) if positions else None})
                    recall_ci, fpr_ci = measured["recall_interval_95"], measured["fpr_interval_95"]
                    row.update(status="ok", error="", threshold=threshold, feasible=operating["feasible"], useful=operating["useful"], **{key: measured[key] for key in ("fpr", "recall", "precision", "pr_auc", "precision_at_k", "k", "zero_score_benign", "zero_score_attack")}, **measured["confusion"], benign_support=measured["support"]["benign"], attack_support=measured["support"]["attack"], recall_lower_95=recall_ci[0], recall_upper_95=recall_ci[1], fpr_lower_95=fpr_ci[0], fpr_upper_95=fpr_ci[1])
                    prediction_rows.extend(candidate_predictions)
                    class_rows.extend(candidate_classes)
                except Exception as error:
                    entry["variants"][variant] = {"status": "failed", "error": f"{type(error).__name__}: {error}"}
                    row.update(status="failed", error=entry["variants"][variant]["error"])
                row["wall_seconds"] = time.perf_counter() - begun
                metric_rows.append(row)
        selection = _select_candidate(candidates)
        for filename, fields, rows in (("candidate_metrics.csv", METRIC_FIELDS, metric_rows), ("validation_predictions.csv", PREDICTION_FIELDS, prediction_rows), ("per_class_validation.csv", CLASS_FIELDS, class_rows)):
            with (stage / filename).open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=fields)
                writer.writeheader()
                writer.writerows(rows)
        _dump(stage / "candidate_metrics.json", {"schema_version": 1, "candidate_order": [name for name, _ in CANDIDATES], "candidates": candidates})
        _dump(stage / "selection.json", selection)
        optional_outputs = []
        if charts:
            try:
                from .ablation_plot import write_ablation_chart
                optional_outputs.append(write_ablation_chart(stage))
            except ImportError as error:
                raise ValueError("Ablation charts require the optional plotting dependencies") from error
        lines = ["# Validation-only class-weight ablation", "", "Only training and validation cohorts are loaded. No source test scores/metrics or serialized models are read, and no test predictions are generated. This development comparison does not create a fresh holdout or establish security effectiveness.", "", "Fixed class-weight order: unweighted, balanced, balanced_subsample. Every other forest setting, ordered feature policy, training/validation cohort and temporal boundary is unchanged across candidates and matched across releases. Identity preprocessing is used. Thresholds are selected separately on each variant's validation set under its recorded FPR ceiling.", "", "| Candidate | Variant | Status | Validation recall | Validation FPR | Precision@K | Zero-score benign | Zero-score attacks |", "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |"]
        for row in metric_rows:
            values = [row.get(key, "null") for key in ("candidate", "variant", "status", "recall", "fpr", "precision_at_k", "zero_score_benign", "zero_score_attack")]
            lines.append("| " + " | ".join(str(value).replace("|", "\\|").replace("\n", " ") for value in values) + " |")
        lines.extend(["", f"Best joint validation candidate: {selection['best_candidate']}. Promoted candidate: {selection['promoted_candidate']}. Promotion passed: {selection['promotion_passed']}.", "", selection["reason"], "", selection["rule"], "", "Candidate failures remain in candidate_metrics.json/CSV; failed candidates cannot win. A nonzero permitted validation true-positive count makes useful=True, which is not an operational usefulness claim. Zero-score overlap exposes tied benign/attack scores that threshold movement cannot separate. Per-class validation support, unseen status and null recall for unsupported classes are retained in per_class_validation.csv.", "", "FPR/recall Wilson intervals assume independent flows; they do not account for temporal correlation, repeated candidate selection or validate the model on future captures. Validation AP is average precision. Scores are model outputs, not established enterprise attack probabilities. No models are promoted into the original immutable run and no fitted-model bundle is persisted here.", "", "Capture-date timing uncertainty, original source-padding accounting, duplicate/label conflicts, independent release samples and prior exploratory use of test captures remain limitations of the frozen source experiment. This ablation does not resolve them.", ""])
        if optional_outputs:
            lines.extend([f"[{name}]({name})" for name in optional_outputs] + [""])
        (stage / "report.md").write_text("\n".join(lines), encoding="utf-8")
        if any(_sha(source / name) != expected for name, expected in hashes.items()):
            raise ValueError("Frozen source artifacts changed during validation ablation")
        provenance = {"schema_version": 1, "source_run": str(source), "source_files": hashes, "cohorts": cohort_hashes, "feature_allowlist": features, "feature_units": config["feature_units"], "temporal_basis": config.get("temporal_basis", "event_time"), "boundaries": config["boundaries"], "forest_settings": parameters, "candidate_order": [name for name, _ in CANDIDATES], "fpr_target": settings["fpr_target"], "alert_budget": settings["alert_budget"], "environment": environment_versions(), "wall_seconds": time.perf_counter() - started, "implementation_sha256": {name: _sha(Path(__file__).parent / name) for name in ("tune.py", "evaluate.py")}, "test_access_policy": "Test rows skipped before label/feature conversion; source predictions.csv and metrics.json are never opened; no test scoring.", "optional_outputs": optional_outputs}
        _dump(stage / "provenance.json", provenance)
        stage.rename(output)
        return output
    except Exception:
        shutil.rmtree(stage)
        raise
