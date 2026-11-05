"""Validation-only fixed 27-versus-39 feature ablation on frozen cohorts."""

from __future__ import annotations

from collections import Counter
import csv
import hashlib
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
from .prepare import FEATURES
from .tune import CLASS_FIELDS, METRIC_FIELDS, PREDICTION_FIELDS, SOURCE_FILES, _csv, _hash_object, _json, _load_cohorts, _sha


CANDIDATE_ORDER = ["baseline27", "expanded39"]
RAW_FIELDS = [f"{direction}_iat_{statistic}" for direction in ("fwd", "bwd") for statistic in ("mean", "std", "max", "min")]
DERIVED_FIELDS = ["fwd_packet_fraction", "fwd_byte_fraction", "fwd_bytes_per_packet", "bwd_bytes_per_packet"]
EXTRA_ORDER = RAW_FIELDS + DERIVED_FIELDS
EXTRA_METADATA = ["variant", "record_id", "partition", "disposition", "duplicate_group_id"]


def _cohort_hashes(cohorts):
    hashes = {}
    for variant, cohort in cohorts.items():
        hashes[variant] = {}
        for partition in ("train", "validation"):
            mask = cohort[partition]
            rows = [row for row, included in zip(cohort["records"], mask) if included]
            hashes[variant][partition] = {"rows": len(rows), "ordered_record_ids_sha256": _hash_object([row["record_id"] for row in rows]), "labels_and_families_sha256": _hash_object([(row["binary_label"], row["source_label"], row["family"]) for row in rows]), "feature_matrix_sha256": hashlib.sha256(np.ascontiguousarray(cohort["matrix"][mask], dtype="<f8").tobytes()).hexdigest(), "ordered_duplicate_group_ids_sha256": _hash_object([row["duplicate_group_id"] for row in rows])}
    return hashes


def _derived_values(values):
    fwd, bwd = values["total_fwd_packets"], values["total_bwd_packets"]
    fbytes, bbytes = values["total_fwd_bytes"], values["total_bwd_bytes"]
    if any(not math.isfinite(value) or value < 0 for value in (fwd, bwd, fbytes, bbytes)):
        raise ValueError("Derived feature counts/bytes must be finite and nonnegative")
    def divide(numerator, denominator):
        return numerator / denominator if denominator else 0.0
    return [divide(fwd, fwd + bwd), divide(fbytes, fbytes + bbytes), divide(fbytes, fwd), divide(bbytes, bwd)]


def _load_extra_features(feature_dir, cohorts, config, source_hashes):
    from .feature_extract import EXTRA_FEATURES

    summary = _json(feature_dir / "summary.json")
    provenance = _json(feature_dir / "provenance.json")
    if summary.get("schema_version") != 1 or summary.get("status") != "ok" or summary.get("invalid_retained_rows") != 0 or summary.get("invalid_retained_feature_values") != 0:
        raise ValueError("Extra-feature extraction did not pass retained-row validation; no cohort may be dropped or fitted")
    if list(EXTRA_FEATURES) != EXTRA_ORDER or summary.get("feature_order") != EXTRA_ORDER or provenance.get("feature_order") != EXTRA_ORDER or provenance.get("feature_definitions") != EXTRA_FEATURES:
        raise ValueError("Extra feature definitions/order differ from the fixed Experiment 004 block")
    if provenance.get("schema_version") != 1 or provenance.get("source_files") != source_hashes or provenance.get("cohorts") != _cohort_hashes(cohorts):
        raise ValueError("Extra features do not reference the exact frozen source cohorts/order/base matrices")
    if provenance.get("extended_features_sha256") != _sha(feature_dir / "extended_features.csv"):
        raise ValueError("Extracted feature artifact hash differs from extraction provenance")
    archives = provenance.get("archives", {})
    if not isinstance(archives, dict) or set(archives) != set(cohorts):
        raise ValueError("Extraction archive identities do not cover the frozen variants")
    for dataset in config["datasets"]:
        expected_archive = dataset.get("preparation", {}).get("archive_sha256")
        if not expected_archive or archives[dataset["variant"]].get("archive_sha256") != expected_archive:
            raise ValueError("Extraction archive identity differs from frozen preparation")
    locations = {row["record_id"]: (variant, index) for variant, cohort in cohorts.items() for index, row in enumerate(cohort["records"])}
    matrices = {variant: np.empty((len(cohort["records"]), len(EXTRA_ORDER)), dtype=float) for variant, cohort in cohorts.items()}
    observed, orders = set(), {variant: [] for variant in cohorts}
    for row in _csv(feature_dir / "extended_features.csv", EXTRA_METADATA + EXTRA_ORDER, exact=EXTRA_METADATA + EXTRA_ORDER):
        if row["partition"] == "test":
            continue
        if row["disposition"] != "retained":
            if row["disposition"] != "quarantined" or row["partition"] not in ("train", "validation"):
                raise ValueError("Unexpected extra-feature diagnostic disposition/partition")
            continue  # Diagnostic duplicates never enter a candidate matrix.
        identifier = row["record_id"]
        if identifier not in locations or identifier in observed:
            raise ValueError("Missing, duplicate or unknown retained extra-feature record ID")
        variant, index = locations[identifier]
        source_row = cohorts[variant]["records"][index]
        if row["variant"] != variant or any(row[key] != source_row[key] for key in ("partition", "disposition", "duplicate_group_id")):
            raise ValueError("Extra-feature metadata disagrees with the frozen row")
        try:
            values = [float(row[name]) for name in EXTRA_ORDER]
        except ValueError as error:
            raise ValueError("Nonnumeric retained extra feature; no rows may be removed") from error
        if not all(math.isfinite(value) for value in values):
            raise ValueError("Nonfinite retained extra feature; no rows may be removed")
        if any(value < 0 for value in values) or any(value > 1 for value in values[8:10]):
            raise ValueError("Retained extra gap/ratio features violate the preregistered nonnegative/fraction-range policy")
        base = dict(zip(config["feature_allowlist"], cohorts[variant]["matrix"][index]))
        expected = _derived_values(base)
        if not all(math.isclose(actual, required, rel_tol=1e-12, abs_tol=1e-12) for actual, required in zip(values[-4:], expected)):
            raise ValueError("Derived extra feature disagrees with the frozen base inputs/zero-denominator convention")
        matrices[variant][index] = values
        observed.add(identifier)
        orders[variant].append(identifier)
    if observed != set(locations):
        raise ValueError("Extra-feature file is missing retained training/validation IDs")
    for variant, cohort in cohorts.items():
        if orders[variant] != [row["record_id"] for row in cohort["records"]]:
            raise ValueError("Retained extra-feature row order differs from the frozen cohort")
    return matrices, summary, provenance, EXTRA_FEATURES


def _select_candidate(candidates):
    tolerance = 1e-12
    expected = set(candidates["baseline27"]["variants"])
    for name in CANDIDATE_ORDER:
        candidate = candidates[name]
        values = list(candidate["variants"].values())
        successful = bool(values) and set(candidate["variants"]) == expected and all(value["status"] == "ok" for value in values)
        candidate["eligible"] = successful and all(value["validation"]["fpr"] <= value["threshold_policy"]["fpr_target"] for value in values)
        candidate["mean_validation_recall"] = float(np.mean([value["validation"]["recall"] for value in values])) if successful else None
        candidate["mean_validation_fpr"] = float(np.mean([value["validation"]["fpr"] for value in values])) if successful else None
    eligible = [name for name in CANDIDATE_ORDER if candidates[name]["eligible"]]
    best = min(eligible, key=lambda name: (-candidates[name]["mean_validation_recall"], candidates[name]["mean_validation_fpr"], CANDIDATE_ORDER.index(name))) if eligible else None
    reference = candidates["baseline27"]
    advance = False
    reason = "No jointly FPR-eligible candidate; retain the frozen baseline."
    if best is not None and reference["eligible"]:
        winner = candidates[best]
        improve = winner["mean_validation_recall"] > reference["mean_validation_recall"] + tolerance
        nonregression = all(winner["variants"][variant]["validation"]["recall"] >= value["validation"]["recall"] - tolerance for variant, value in reference["variants"].items())
        advance = best == "expanded39" and improve and nonregression
        reason = "Expanded block advances: mean validation recall improves and neither variant recall regresses." if advance else "Retain baseline27: no qualifying mean improvement or at least one variant recall regression."
    elif best is not None:
        reason = "Baseline reproduction failed or violates FPR constraint; improvement over it is not established."
    return {"reference_candidate": "baseline27", "best_candidate": best, "promoted_candidate": "expanded39" if advance else "baseline27", "promotion_passed": advance, "promotion_tolerance": tolerance, "candidate_order": CANDIDATE_ORDER, "reason": reason, "rule": "Rank by greater unweighted mean variant validation recall, then lower mean FPR, then baseline27. Each variant must satisfy its FPR ceiling. Advance expanded39 only if mean recall improves by more than 1e-12 and no variant recall regresses by more than 1e-12.", "scope": "Validation only; no test scores or results accessed."}


def run_feature_ablation(source_run: str | Path, feature_dir: str | Path, output_dir: str | Path, *, charts=False) -> Path:
    started = time.perf_counter()
    source, extra_dir, output = Path(source_run).resolve(), Path(feature_dir).resolve(), Path(output_dir).resolve()
    if not source.is_dir() or not extra_dir.is_dir() or output.exists() or output.is_relative_to(source) or output.is_relative_to(extra_dir):
        raise ValueError("Feature ablation needs frozen source/features and a new output directory outside both")
    source_hashes = {name: _sha(source / name) for name in SOURCE_FILES}
    feature_hashes = {name: _sha(extra_dir / name) for name in ("summary.json", "provenance.json", "extended_features.csv")}
    config, manifest = _json(source / "config.json"), _json(source / "manifest.json")
    _validate(config)
    expected_features = [value[0] for value in FEATURES.values()]
    expected_units = {value[0]: value[1] for value in FEATURES.values()}
    if config["feature_allowlist"] != expected_features or config["feature_units"] != expected_units:
        raise ValueError("Experiment 004 requires the exact ordered 27-feature base policy and units")
    cohorts, settings = _load_cohorts(source, config, manifest)
    extras, extraction_summary, extraction_provenance, definitions = _load_extra_features(extra_dir, cohorts, config, source_hashes)
    parameters = {key: settings[key] for key in ("n_estimators", "max_depth", "min_samples_leaf", "n_jobs")}
    parameters.update(random_state=settings["seed"], class_weight="balanced_subsample", max_features="sqrt")
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".feature-ablation-", dir=output.parent))
    try:
        candidates, metrics, predictions, classes = {}, [], [], []
        for name in CANDIDATE_ORDER:
            entry = candidates[name] = {"feature_count": 27 if name == "baseline27" else 39, "class_weight": "balanced_subsample", "variants": {}}
            for variant, cohort in cohorts.items():
                begun = time.perf_counter()
                matrix = cohort["matrix"] if name == "baseline27" else np.column_stack((cohort["matrix"], extras[variant]))
                train, valid, labels, records = (cohort[key] for key in ("train", "validation", "labels", "records"))
                training_support = {"benign": int(np.sum(labels[train] == 0)), "attack": int(np.sum(labels[train] == 1))}
                row = {"candidate": name, "feature_count": matrix.shape[1], "class_weight": "balanced_subsample", "variant": variant, "training_benign": training_support["benign"], "training_attack": training_support["attack"]}
                try:
                    candidate_predictions, candidate_classes = [], []
                    pipeline = Pipeline([("preprocessing", "passthrough"), ("classifier", RandomForestClassifier(**parameters))])
                    pipeline.fit(matrix[train], labels[train])
                    scores = attack_scores(pipeline, matrix[valid])
                    operating = select_threshold(labels[valid], scores, settings["fpr_target"])
                    threshold = operating["threshold"]
                    valid_records = [record for record, included in zip(records, valid) if included]
                    measured = binary_metrics(labels[valid], scores, threshold, [record["record_id"] for record in valid_records], settings["alert_budget"])
                    operating["validation_metrics"] = measured
                    measured = dict(measured, zero_score_benign=int(np.sum((scores == 0) & (labels[valid] == 0))), zero_score_attack=int(np.sum((scores == 0) & (labels[valid] == 1))))
                    for record, score in zip(valid_records, scores):
                        candidate_predictions.append({"variant": variant, "candidate": name, "record_id": record["record_id"], "partition": "validation", "source_label": record["source_label"], "family": record["family"], "binary_label": int(record["binary_label"]), "attack_score": float(score), "threshold": threshold, "prediction": int(score >= threshold)})
                    training_families = Counter(record["family"] for record, included in zip(records, train) if included)
                    for family in sorted({record["family"] for record in records}):
                        positions = [index for index, record in enumerate(valid_records) if record["family"] == family]
                        role = next(int(record["binary_label"]) for record in records if record["family"] == family)
                        hits = sum(scores[index] >= threshold for index in positions)
                        zeros = sum(scores[index] == 0 for index in positions)
                        candidate_classes.append({"candidate": name, "variant": variant, "family": family, "binary_label": role, "training_support": training_families[family], "validation_support": len(positions), "seen_in_training": bool(training_families[family]), "binary_detection_recall": float(hits / len(positions)) if positions and role else None, "zero_score_support": int(zeros), "zero_score_fraction": float(zeros / len(positions)) if positions else None})
                    rci, fci = measured["recall_interval_95"], measured["fpr_interval_95"]
                    row.update(status="ok", error="", threshold=threshold, feasible=operating["feasible"], useful=operating["useful"], **{key: measured[key] for key in ("fpr", "recall", "precision", "pr_auc", "precision_at_k", "k", "zero_score_benign", "zero_score_attack")}, **measured["confusion"], benign_support=measured["support"]["benign"], attack_support=measured["support"]["attack"], recall_lower_95=rci[0], recall_upper_95=rci[1], fpr_lower_95=fci[0], fpr_upper_95=fci[1])
                    entry["variants"][variant] = {"status": "ok", "threshold_policy": operating, "validation": measured, "training_support": training_support}
                    predictions.extend(candidate_predictions)
                    classes.extend(candidate_classes)
                except Exception as error:
                    entry["variants"][variant] = {"status": "failed", "error": f"{type(error).__name__}: {error}"}
                    row.update(status="failed", error=entry["variants"][variant]["error"])
                row["wall_seconds"] = time.perf_counter() - begun
                metrics.append(row)
        selection = _select_candidate(candidates)
        for filename, fields, rows in (("candidate_metrics.csv", [*METRIC_FIELDS, "feature_count"], metrics), ("validation_predictions.csv", PREDICTION_FIELDS, predictions), ("per_class_validation.csv", CLASS_FIELDS, classes)):
            with (stage / filename).open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=fields)
                writer.writeheader()
                writer.writerows(rows)
        _dump(stage / "candidate_metrics.json", {"schema_version": 1, "candidate_order": CANDIDATE_ORDER, "candidates": candidates})
        _dump(stage / "selection.json", selection)
        optional = []
        if charts:
            try:
                from .feature_plot import write_feature_chart
                optional.append(write_feature_chart(stage))
            except ImportError as error:
                raise ValueError("Feature-ablation chart requires plotting dependencies") from error
        lines = ["# Validation-only fixed feature-block ablation", "", "Compare baseline27 with expanded39 using the same balanced_subsample forest and frozen training/validation cohorts. No test-result file, test matrix or serialized model is read; no test predictions are generated. Prior exploratory capture use and validation model-selection limitations remain.", "", "Added block: eight directional IAT statistics plus four deterministic fractions/bytes-per-packet quantities, with zero denominators mapped to zero. All retained added features passed explicit finite/value/identity checks; no rows were dropped or imputed. The original 27-feature duplicate dispositions remain frozen even where added raw features distinguish previous projection ties. Derived features cannot separate identical base projections.", "", "Both models use max_features='sqrt': effectively five candidate columns per split for 27 inputs and six for 39. This dimension-dependent behavior is part of the fixed policy, not additional parameter tuning. Neither equal field definitions nor increased feature width establishes matched flows or a causal correction effect.", "", "| Candidate | Variant | Features | Status | Validation recall | Validation FPR | Precision@K |", "| --- | --- | ---: | --- | ---: | ---: | ---: |"]
        for row in metrics:
            lines.append("| " + " | ".join(str(row.get(key, "null")) for key in ("candidate", "variant", "feature_count", "status", "recall", "fpr", "precision_at_k")) + " |")
        lines.extend(["", f"Best joint validation candidate: {selection['best_candidate']}. Advancement recommendation: {selection['promoted_candidate']}. Passed: {selection['promotion_passed']}.", "", selection["reason"], "", selection["rule"], "", "All candidate outcomes, including failures, are published. Useful=True means nonzero permitted validation true positives, not established operational utility. Family support/recall and zero-score overlap are exported. Wilson intervals assume independent flows and do not account for capture-day correlation or repeated validation selection. Models are not persisted or installed into the frozen source experiment.", ""])
        lines.extend([f"[{name}]({name})" for name in optional] + [""])
        (stage / "report.md").write_text("\n".join(lines), encoding="utf-8")
        if any(_sha(source / name) != expected for name, expected in source_hashes.items()) or any(_sha(extra_dir / name) != expected for name, expected in feature_hashes.items()):
            raise ValueError("Frozen source or extraction artifacts changed during the feature experiment")
        expanded_hashes = {variant: {partition: hashlib.sha256(np.ascontiguousarray(np.column_stack((cohort["matrix"], extras[variant]))[cohort[partition]], dtype="<f8").tobytes()).hexdigest() for partition in ("train", "validation")} for variant, cohort in cohorts.items()}
        _dump(stage / "provenance.json", {"schema_version": 1, "source_run": str(source), "source_files": source_hashes, "feature_dir": str(extra_dir), "feature_files": feature_hashes, "cohorts": _cohort_hashes(cohorts), "expanded_feature_matrix_hashes": expanded_hashes, "base_feature_order": expected_features, "extra_feature_order": EXTRA_ORDER, "feature_definitions": definitions, "forest_settings": parameters, "fpr_target": settings["fpr_target"], "alert_budget": settings["alert_budget"], "candidate_order": CANDIDATE_ORDER, "environment": environment_versions(), "wall_seconds": time.perf_counter() - started, "implementation_sha256": {name: _sha(Path(__file__).parent / name) for name in ("feature_ablation.py", "feature_extract.py", "tune.py", "evaluate.py")}, "extraction_status": extraction_summary["status"], "test_access_policy": "Test rows skipped before semantic label/feature conversion; source/earlier metrics and predictions are never opened.", "optional_outputs": optional})
        stage.rename(output)
        return output
    except Exception:
        shutil.rmtree(stage)
        raise
