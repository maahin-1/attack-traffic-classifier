"""Versioned trusted-local model persistence and strict batch inference."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import os
import platform
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path

import joblib
import numpy as np
import sklearn

from .audit import _feature_safe, _name


def environment_versions() -> dict:
    return {"python": ".".join(platform.python_version().split(".")[:2]), "scikit_learn": sklearn.__version__, "numpy": np.__version__, "joblib": joblib.__version__}


def _digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def save_model(model_dir: Path, bundle: dict, metadata: dict) -> None:
    """Persist only into a new directory within an unpublished experiment."""
    model_dir.mkdir(parents=True, exist_ok=False)
    bundle = dict(bundle, threshold=metadata["threshold"], feature_units=metadata["feature_units"], environment=environment_versions())
    joblib.dump(bundle, model_dir / "bundle.joblib")
    metadata = dict(metadata, schema_version=1, environment=environment_versions(), bundle_sha256=_digest(model_dir / "bundle.joblib"))
    (model_dir / "metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


def load_model(model_dir: str | Path) -> tuple[dict, dict]:
    """Load only artifacts the caller trusts; joblib can execute Python code.

    Metadata/environment/hash checks detect incompatibility and accidental damage;
    they do not make an untrusted serialized model safe to load.
    """
    directory = Path(model_dir)
    try:
        metadata = json.loads((directory / "metadata.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read model metadata: {exc}") from exc
    if not isinstance(metadata, dict) or metadata.get("schema_version") != 1:
        raise ValueError("Unsupported model metadata schema_version")
    if metadata.get("environment") != environment_versions():
        raise ValueError("Model environment versions differ; use the exact training environment")
    features = metadata.get("feature_allowlist")
    if not isinstance(features, list) or not features or not all(isinstance(name, str) and _name(name) == name and _feature_safe(name) for name in features) or len(set(features)) != len(features):
        raise ValueError("Model metadata contains an unsafe or invalid feature allowlist")
    units = metadata.get("feature_units")
    if not isinstance(units, dict) or any(not isinstance(units.get(name), str) or not units[name] for name in features):
        raise ValueError("Model metadata lacks documented feature units")
    threshold = metadata.get("threshold")
    if not isinstance(threshold, (int, float)) or not math.isfinite(threshold):
        raise ValueError("Model metadata lacks a finite frozen threshold")
    try:
        if _digest(directory / "bundle.joblib") != metadata.get("bundle_sha256"):
            raise ValueError("Model bundle hash mismatch")
        bundle = joblib.load(directory / "bundle.joblib")
    except OSError as exc:
        raise ValueError(f"Cannot read model bundle: {exc}") from exc
    if not isinstance(bundle, dict) or bundle.get("schema_version") != 1 or bundle.get("feature_allowlist") != features or bundle.get("model_id") != metadata.get("model_id"):
        raise ValueError("Model bundle and metadata schema mismatch")
    if bundle.get("threshold") != threshold or bundle.get("feature_units") != units or bundle.get("environment") != metadata["environment"]:
        raise ValueError("Model bundle and metadata scoring contract mismatch")
    if not all(key in bundle for key in ("binary_pipeline", "family_pipeline")):
        raise ValueError("Model bundle is incomplete")
    return bundle, metadata


def score_model(model_dir: str | Path, input_path: str | Path, output_path: str | Path) -> Path:
    """Score canonical feature-only CSVs, optionally carrying record_id.

    Write atomically and reject existing outputs; invalid data never becomes a
    benign prediction. No labels or identifiers other than record_id are accepted.
    """
    from .evaluate import attack_scores

    bundle, metadata = load_model(model_dir)
    features = metadata["feature_allowlist"]
    output = Path(output_path).resolve()
    if output.exists():
        raise ValueError(f"Score output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".scores-", suffix=".csv", dir=output.parent)
    os.close(descriptor)
    stage = Path(temporary)
    ids_path = stage.with_suffix(".sqlite")
    try:
        with closing(sqlite3.connect(ids_path)) as ids_database, Path(input_path).open("r", newline="", encoding="utf-8-sig") as source, stage.open("w", newline="", encoding="utf-8") as destination:
            ids_database.execute("CREATE TABLE ids (identifier TEXT PRIMARY KEY) WITHOUT ROWID")
            reader = csv.DictReader(source)
            headers = reader.fieldnames or []
            if len(headers) != len(set(headers)) or set(headers) not in (set(features), set(features) | {"record_id"}):
                raise ValueError("Score input schema must contain exactly canonical allowed features and optional record_id")
            writer = csv.DictWriter(destination, fieldnames=["record_id", "model_id", "attack_score", "threshold", "prediction", "class_prediction"])
            writer.writeheader()
            batch, identifiers = [], []
            total = 0

            def flush():
                if not batch:
                    return
                matrix = np.asarray(batch, dtype=float)
                scores = attack_scores(bundle["binary_pipeline"], matrix)
                families = bundle["family_pipeline"].predict(matrix)
                for record_id, score, family in zip(identifiers, scores, families):
                    writer.writerow({"record_id": record_id, "model_id": metadata["model_id"], "attack_score": float(score), "threshold": metadata["threshold"], "prediction": int(score >= metadata["threshold"]), "class_prediction": str(family)})
                batch.clear()
                identifiers.clear()

            for number, row in enumerate(reader, 2):
                if None in row or any(value is None for value in row.values()):
                    raise ValueError(f"Malformed score CSV row {number}")
                try:
                    values = [float(row[feature]) for feature in features]
                except ValueError as exc:
                    raise ValueError(f"Nonnumeric model feature at score row {number}") from exc
                if not all(math.isfinite(value) for value in values):
                    raise ValueError(f"Nonfinite model feature at score row {number}")
                if any("duration" in name and value < 0 for name, value in zip(features, values)):
                    raise ValueError(f"Invalid duration at score row {number}")
                identifier = row.get("record_id", str(number - 1))
                if not identifier.strip():
                    raise ValueError(f"Empty record_id at score row {number}")
                try:
                    ids_database.execute("INSERT INTO ids VALUES (?)", (identifier,))
                except sqlite3.IntegrityError as exc:
                    raise ValueError(f"Duplicate record_id at score row {number}") from exc
                batch.append(values)
                identifiers.append(identifier)
                total += 1
                if len(batch) >= 1000:
                    flush()
            if not total:
                raise ValueError("Score input contains no data rows")
            flush()
        ids_path.unlink()
        stage.rename(output)
        return output
    except Exception:
        stage.unlink(missing_ok=True)
        ids_path.unlink(missing_ok=True)
        raise
