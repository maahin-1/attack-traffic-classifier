"""Bounded chronological baseline experiments with validation-only thresholds."""

from __future__ import annotations

import copy
import csv
import hashlib
import json
import os
import platform
import re
import shutil
import tempfile
import time
from pathlib import Path

import numpy as np
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline

from .audit import TIME_FIELDS, _dump, _validate, run_audit
from .config import load_config
from .evaluate import attack_scores, binary_metrics, select_threshold
from .model import environment_versions, save_model


def _training_config(config: dict) -> dict:
    training = dict(seed=42, n_estimators=200, max_depth=12, min_samples_leaf=2, n_jobs=1, max_rows_per_variant=100000, fpr_target=0.01, alert_budget=100)
    supplied = config.get("training", {})
    if not isinstance(supplied, dict):
        raise ValueError("training must be an object")
    unknown = set(supplied) - set(training)
    if unknown:
        raise ValueError(f"Unknown training settings: {sorted(unknown)}")
    training.update(supplied)
    for key in ("seed", "n_estimators", "max_depth", "min_samples_leaf", "n_jobs", "max_rows_per_variant", "alert_budget"):
        if type(training[key]) is not int or training[key] < (0 if key == "seed" else 1):
            raise ValueError(f"training.{key} must be {'nonnegative' if key == 'seed' else 'positive'} integer")
    if not isinstance(training["fpr_target"], (float, int)) or not 0 <= training["fpr_target"] <= 1:
        raise ValueError("training.fpr_target must be in [0,1]")
    if config.get("profile", "synthetic") not in ("synthetic", "subset", "full"):
        raise ValueError("profile must be synthetic, subset or full")
    for dataset in config.get("datasets", []):
        if not isinstance(dataset, dict) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", str(dataset.get("variant", ""))):
            raise ValueError("Variant must be a safe directory name using letters, digits, hyphens or underscores")
    return training


def _load_variant(audit: Path, variant: str, features: list[str], cap: int):
    records = []
    with (audit / "splits.csv").open(newline="", encoding="utf-8") as stream:
        for row in csv.DictReader(stream):
            if row["variant"] == variant and row["disposition"] == "retained":
                if len(records) >= cap:
                    raise ValueError(f"Variant {variant} exceeds max_rows_per_variant={cap}; increase the explicit cap or prepare a declared subset")
                records.append(row)
    if not records:
        raise ValueError(f"Variant {variant} has no retained rows")
    index = {row["record_id"]: position for position, row in enumerate(records)}
    if len(index) != len(records):
        raise ValueError("Retained audit contains duplicate record IDs")
    matrix = np.empty((len(records), len(features)), dtype=float)
    observed = set()
    with (audit / "retained_features.csv").open(newline="", encoding="utf-8") as stream:
        for row in csv.DictReader(stream):
            if row["variant"] != variant:
                continue
            identifier = row["record_id"]
            if identifier not in index or identifier in observed:
                raise ValueError("Retained feature IDs do not match split audit")
            matrix[index[identifier]] = [float(row[feature]) for feature in features]
            observed.add(identifier)
    if len(observed) != len(records) or not np.isfinite(matrix).all():
        raise ValueError("Retained feature export is incomplete or nonfinite")
    labels = np.asarray([int(row["binary_label"]) for row in records])
    families = np.asarray([row["family"] for row in records])
    partitions = np.asarray([row["partition"] for row in records])
    masks = {part: partitions == part for part in ("train", "validation", "test")}
    for part in ("train", "validation"):
        if set(labels[masks[part]]) != {0, 1}:
            raise ValueError(f"Variant {variant} {part} requires both binary classes; inspect audit inventory and revise boundaries without test scores")
    if not masks["test"].any():
        raise ValueError(f"Variant {variant} requires nonempty test support")
    return records, matrix, labels, families, masks


def _forest(training: dict):
    return RandomForestClassifier(n_estimators=training["n_estimators"], max_depth=training["max_depth"], min_samples_leaf=training["min_samples_leaf"], n_jobs=training["n_jobs"], random_state=training["seed"], class_weight=None)


def _resources() -> dict:
    peak = None
    method = "unavailable"
    try:
        import psutil
        info = psutil.Process().memory_info()
        if hasattr(info, "peak_wset"):
            peak, method = info.peak_wset, "Windows process lifetime peak working set"
    except ImportError:
        pass
    if peak is None and os.name != "nt":
        import resource
        usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        peak = usage if platform.system() == "Darwin" else usage * 1024
        method = "process lifetime ru_maxrss"
    return {"peak_resident_bytes": peak, "peak_memory_method": method, "cpu_count": os.cpu_count(), "processor": platform.processor(), "platform": platform.platform(), "environment": environment_versions()}


def run_experiment(config_path: str | Path) -> Path:
    """Audit, fit bounded baselines and freeze validation thresholds before test."""
    begun = time.perf_counter()
    config_path = Path(config_path).resolve()
    config = load_config(config_path)
    _validate(config)
    for dataset in config["datasets"]:
        adapter = dict(config)
        for key in ("timestamp_format", "timezone", "label_map", "label_map_version"):
            if key in dataset:
                adapter[key] = dataset[key]
        adapter["datasets"] = [dataset]
        _validate(adapter)
    training = _training_config(config)
    if not isinstance(config.get("output_dir"), str) or not config["output_dir"]:
        raise ValueError("output_dir is required")
    output = (config_path.parent / config["output_dir"]).resolve()
    if output.exists():
        raise ValueError(f"Run directory already exists: {output}; choose a new output_dir")
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".experiment-", dir=output.parent))
    try:
        audit_config = copy.deepcopy(config)
        audit_config["output_dir"] = str(stage / "audit")
        for dataset in audit_config["datasets"]:
            dataset["files"] = [str((config_path.parent / path).resolve()) for path in dataset["files"]]
        _dump(stage / "audit-input.json", audit_config)
        audit = run_audit(stage / "audit-input.json")
        (stage / "audit-input.json").unlink()
        audit_manifest = json.loads((audit / "manifest.json").read_text(encoding="utf-8"))
        features = config["feature_allowlist"]
        metrics = {}
        total_retained = 0
        with (stage / "predictions.csv").open("w", newline="", encoding="utf-8") as prediction_stream, (stage / "per_class.csv").open("w", newline="", encoding="utf-8") as class_stream:
            prediction_fields = ["variant", "model_id", "model", "record_id", "partition", "source_label", "family", "binary_label", "attack_score", "threshold", "prediction", "class_prediction", "event_start", *TIME_FIELDS]
            predictions = csv.DictWriter(prediction_stream, fieldnames=prediction_fields)
            predictions.writeheader()
            class_fields = ["variant", "model", "family", "training_support", "test_support", "seen_in_training", "binary_detection_recall", "family_attribution_recall"]
            class_writer = csv.DictWriter(class_stream, fieldnames=class_fields)
            class_writer.writeheader()
            for dataset in config["datasets"]:
                variant = dataset["variant"]
                records, matrix, labels, families, masks = _load_variant(audit, variant, features, training["max_rows_per_variant"])
                total_retained += len(records)
                train, validation, test = (masks[part] for part in ("train", "validation", "test"))
                label_map = dataset.get("label_map", config.get("label_map", {}))
                family_names = sorted(set(families) | {mapping["family"] for mapping in label_map.values()})
                family_binary = {}
                for family in family_names:
                    values = set(int(value) for value in labels[families == family]) | {mapping["binary"] for mapping in label_map.values() if mapping["family"] == family}
                    if len(values) != 1:
                        raise ValueError(f"Family {family} mixes binary benign/attack labels; define distinct families")
                    family_binary[family] = next(iter(values))
                family_pipeline = Pipeline([("preprocessing", "passthrough"), ("classifier", _forest(training))])
                family_pipeline.fit(matrix[train], families[train])
                family_predictions = family_pipeline.predict(matrix)
                identity = hashlib.sha256(json.dumps({"config": config, "manifest": audit_manifest["datasets"], "variant": variant}, sort_keys=True).encode()).hexdigest()[:12]
                metrics[variant] = {}
                for model_name, classifier in (("baseline", DummyClassifier(strategy="most_frequent")), ("random_forest", _forest(training))):
                    pipeline = Pipeline([("preprocessing", "passthrough"), ("classifier", classifier)])
                    pipeline.fit(matrix[train], labels[train])
                    # No test score is consulted until this threshold is frozen.
                    validation_scores = attack_scores(pipeline, matrix[validation])
                    operating = select_threshold(labels[validation], validation_scores, training["fpr_target"])
                    threshold = operating["threshold"]
                    ids = np.asarray([row["record_id"] for row in records])
                    operating["validation_metrics"] = binary_metrics(labels[validation], validation_scores, threshold, ids[validation], training["alert_budget"])
                    scores = attack_scores(pipeline, matrix)
                    test_metrics = binary_metrics(labels[test], scores[test], threshold, ids[test], training["alert_budget"])
                    unseen = test & ~np.isin(families, np.unique(families[train])) & (labels == 1)
                    test_metrics["unseen_attack_support"] = int(unseen.sum())
                    test_metrics["unseen_attack_recall"] = float(np.mean(scores[unseen] >= threshold)) if unseen.any() else None
                    model_id = f"{variant}-{model_name}-{identity}"
                    metrics[variant][model_name] = {"model_id": model_id, "threshold_policy": operating, "test": test_metrics}
                    for position, record in enumerate(records):
                        if record["partition"] == "train":
                            continue
                        predictions.writerow({"variant": variant, "model_id": model_id, "model": model_name, "record_id": record["record_id"], "partition": record["partition"], "source_label": record["source_label"], "family": record["family"], "binary_label": int(labels[position]), "attack_score": float(scores[position]), "threshold": threshold, "prediction": int(scores[position] >= threshold), "class_prediction": str(family_predictions[position]) if model_name == "random_forest" else "", "event_start": record["event_start"], **{field: record.get(field, "") for field in TIME_FIELDS}})
                    for family in family_names:
                        train_family, test_family = train & (families == family), test & (families == family)
                        support = int(test_family.sum())
                        detection = float(np.mean(scores[test_family] >= threshold)) if support and family_binary[family] == 1 else None
                        attribution = float(np.mean(family_predictions[test_family] == family)) if support and model_name == "random_forest" else None
                        class_writer.writerow({"variant": variant, "model": model_name, "family": family, "training_support": int(train_family.sum()), "test_support": support, "seen_in_training": bool(train_family.any()), "binary_detection_recall": detection, "family_attribution_recall": attribution})
                    if model_name == "random_forest":
                        save_model(stage / "models" / variant, {"schema_version": 1, "model_id": model_id, "feature_allowlist": features, "binary_pipeline": pipeline, "family_pipeline": family_pipeline}, {"model_id": model_id, "variant": variant, "feature_allowlist": features, "feature_units": config["feature_units"], "threshold": threshold, "training": training, "release": dataset["release"], "label_map": label_map, "label_map_version": dataset.get("label_map_version", config.get("label_map_version")), "trust_note": "Load only trusted local joblib artifacts; checks do not sandbox deserialization."})
                # Drop this variant's full arrays before reading the next variant.
                del matrix, labels, families, masks, records, pipeline, family_pipeline, scores
        wall = time.perf_counter() - begun
        manifest = {"schema_version": 1, "stage": "baseline_experiment", "profile": config.get("profile", "synthetic"), "training": training, "resources": _resources(), "wall_seconds": wall, "retained_rows": total_retained, "retained_rows_per_second": total_retained / wall, "comparison_scope": "pipeline/data-version population comparison; not label-only causal analysis", "datasets": audit_manifest["datasets"], "boundaries": config["boundaries"], "feature_allowlist": features}
        manifest["config_sha256"] = hashlib.sha256(json.dumps(config, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        manifest["temporal_basis"] = config.get("temporal_basis", "event_time")
        manifest["source_sha256"] = {source.name: hashlib.sha256(source.read_bytes()).hexdigest() for source in sorted(Path(__file__).parent.glob("*.py"))}
        _dump(stage / "manifest.json", manifest)
        _dump(stage / "config.json", config)
        _dump(stage / "metrics.json", metrics)
        population_note = "Synthetic fixtures verify execution and invariants only. Their scores do not demonstrate intrusion-detection performance." if manifest["profile"] == "synthetic" else "These results describe the configured local dataset population. A subset run is not a full-release benchmark. Neither profile establishes performance on an enterprise network; capture bias, label uncertainty and future unseen attacks limit generalization."
        lines = ["# Baseline experiment", "", f"Profile: {manifest['profile']}. CPU-only models; measured wall time {wall:.3f} seconds.", "", population_note, "", "A majority constant baseline and one declared bounded random forest use identical numeric features and time boundaries across variants. Identity preprocessing is saved inside each pipeline; no scaling or validation/test rebalancing is performed.", "", "Thresholds maximize validation attack recall under the configured benign FPR ceiling; no test retuning occurs. Infeasible/useful status is preserved in metrics.json. Test outcomes are reported without changing that threshold.", "", "Family attribution is a separate closed-set diagnostic. Unseen attacks may be detected in binary scoring but cannot be learned as absent families. Inspect per_class.csv and unseen_attack_recall in metrics.json.", "", "The comparison includes reconstructed-flow population differences and is not a label-only causal experiment. Start-time coverage does not establish complete capture days; no measured daily false-alert claim is made.", "", "See audit/report.md for row accounting, timing limitations and duplicate policy. Model inputs exclude metadata; models use no packet capture or outbound network traffic.", ""]
        lines.extend(["| Variant | Model | Frozen threshold | Useful validation point | Test FPR | Test recall | Test precision | Test precision@K | Test benign/attack support |", "| --- | --- | ---: | --- | ---: | ---: | ---: | ---: | --- |"])
        def display(value):
            return "null" if value is None else f"{value:.6g}"
        for variant, model_metrics in metrics.items():
            for model_name, result in model_metrics.items():
                test_result = result["test"]
                policy = result["threshold_policy"]
                support = test_result["support"]
                lines.append(f"| {variant} | {model_name} | {display(policy['threshold'])} | {policy['useful']} | {display(test_result['fpr'])} | {display(test_result['recall'])} | {display(test_result['precision'])} | {display(test_result['precision_at_k'])} | {support['benign']}/{support['attack']} |")
        lines.extend(["", f"K=min({training['alert_budget']}, pooled test population), with score descending and stable record ID ascending for ties. The configured random forest has {training['n_estimators']} trees, max_depth={training['max_depth']}, min_samples_leaf={training['min_samples_leaf']}, seed={training['seed']} and n_jobs={training['n_jobs']}.", "", "Confidence intervals in metrics.json are Wilson flow-level intervals that assume independence. They do not address temporal correlation; this stage does not produce temporal-block comparison uncertainty.", ""])
        if manifest["temporal_basis"] == "capture_date":
            lines.extend(["This experiment matches capture-day blocks, not exact UTC instants. Unresolved original AM/PM and timezone remain interval metadata; blank UTC event_start/end values are intentional. Possible partition overlap is conservatively quarantined. Deduplication uses earliest eligible capture date and prepared source order, not established within-day earliest event time.", ""])
        (stage / "report.md").write_text("\n".join(lines), encoding="utf-8")
        (stage / "model_card.md").write_text("# Model card\n\nOffline research classifier. Intended for local dataset-quality experiments, not live network decisions. Binary random forest scores P(attack); a separate family forest supplies diagnostics. Training uses earlier data; thresholds use validation only. Synthetic runs establish software behavior, not security effectiveness. Dataset labels and attempted/effective distinctions remain in audit records and prediction exports. Unknown future families, capture bias, incomplete timing, label uncertainty and reconstructed populations limit generalization. Load only trusted local serialized models in the recorded environment.\n", encoding="utf-8")
        stage.rename(output)
        return output
    except Exception:
        shutil.rmtree(stage)
        raise
