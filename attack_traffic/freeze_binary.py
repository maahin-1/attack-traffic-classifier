"""Reproduce and freeze the selected validation-only binary forest.

Joblib files are executable on load: load only trusted locally generated bundles.
These binary-only bundles are not compatible with the existing family-model CLI.
"""
import csv
import hashlib
import json
import math
import shutil
import tempfile
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline

from .audit import _dump, _validate
from .evaluate import attack_scores, binary_metrics, select_threshold
from .model import environment_versions
from .prepare import FEATURES
from .tune import SOURCE_FILES, _hash_object, _json, _load_cohorts, _sha


def load_binary(directory):
    """Load a trusted-local binary bundle after checking schema, environment and hash."""
    directory = Path(directory)
    metadata = _json(directory / 'metadata.json')
    if metadata.get('schema_version') != 1 or metadata.get('bundle_type') != 'binary_random_forest_v1':
        raise ValueError('Unsupported binary bundle metadata')
    if metadata.get('environment') != environment_versions():
        raise ValueError('Model environment differs from training environment')
    expected_names = [item[0] for item in FEATURES.values()]
    expected_units = {item[0]: item[1] for item in FEATURES.values()}
    threshold = metadata.get('threshold')
    if (metadata.get('feature_allowlist') != expected_names or metadata.get('feature_units') != expected_units
            or isinstance(threshold, bool) or not isinstance(threshold, (int, float))
            or not math.isfinite(threshold)):
        raise ValueError('Invalid binary model feature or threshold contract')
    if _sha(directory / 'bundle.joblib') != metadata.get('bundle_sha256'):
        raise ValueError('Model bundle hash mismatch')
    bundle = joblib.load(directory / 'bundle.joblib')
    if not isinstance(bundle, dict) or bundle.get('schema_version') != 1 or bundle.get('bundle_type') != 'binary_random_forest_v1':
        raise ValueError('Unsupported binary bundle')
    for key in ('variant', 'feature_allowlist', 'feature_units', 'threshold', 'environment'):
        if bundle.get(key) != metadata.get(key):
            raise ValueError('Bundle and metadata differ')
    if 'binary_pipeline' not in bundle:
        raise ValueError('Missing binary pipeline')
    return bundle, metadata


def _check_predictions(pipeline, cohort, settings, reference, expected_rows):
    valid = cohort['validation']
    labels = cohort['labels'][valid]
    records = [row for row, include in zip(cohort['records'], valid) if include]
    scores = attack_scores(pipeline, cohort['matrix'][valid])
    policy = select_threshold(labels, scores, settings['fpr_target'])
    threshold = policy['threshold']
    measured = binary_metrics(labels, scores, threshold, [row['record_id'] for row in records], settings['alert_budget'])
    policy['validation_metrics'] = measured
    measured = dict(measured, zero_score_benign=int(np.sum((scores == 0) & (labels == 0))), zero_score_attack=int(np.sum((scores == 0) & (labels == 1))))
    if policy != reference['threshold_policy'] or measured != reference['validation']:
        raise ValueError('Validation threshold policy or metrics differ from selected reference')
    if len(records) != len(expected_rows):
        raise ValueError('Reference validation count differs')
    for record, score, expected in zip(records, scores, expected_rows):
        if (expected['record_id'] != record['record_id'] or expected['partition'] != 'validation'
                or expected['source_label'] != record['source_label'] or expected['family'] != record['family']
                or expected['binary_label'] != record['binary_label'] or float(expected['attack_score']) != float(score)
                or float(expected['threshold']) != threshold or int(expected['prediction']) != int(score >= threshold)):
            raise ValueError('Validation prediction differs from selected reference')
    return threshold, len(records)


def freeze_binary_models(source_run, reference_dir, output_dir):
    source, reference_dir, output = map(lambda x: Path(x).resolve(), (source_run, reference_dir, output_dir))
    if not source.is_dir() or not reference_dir.is_dir() or output.exists() or output.is_relative_to(source) or output.is_relative_to(reference_dir):
        raise ValueError('Require existing sources and a fresh separate output directory')
    reference_files = ('provenance.json', 'selection.json', 'candidate_metrics.json', 'validation_predictions.csv')
    source_hashes = {name: _sha(source / name) for name in SOURCE_FILES}
    reference_hashes = {name: _sha(reference_dir / name) for name in reference_files}
    provenance = _json(reference_dir / 'provenance.json')
    selection = _json(reference_dir / 'selection.json')
    if provenance.get('source_files') != source_hashes or provenance.get('environment') != environment_versions():
        raise ValueError('Reference source or environment mismatch')
    if selection.get('promoted_candidate') != 'balanced_subsample' or selection.get('promotion_passed') is not True:
        raise ValueError('Balanced subsample was not selected')
    config, manifest = _json(source / 'config.json'), _json(source / 'manifest.json')
    _validate(config)
    if provenance.get('feature_allowlist') != config['feature_allowlist'] or provenance.get('feature_units') != config['feature_units']:
        raise ValueError('Feature contract mismatch')
    if config['feature_allowlist'] != [item[0] for item in FEATURES.values()] or config['feature_units'] != {item[0]: item[1] for item in FEATURES.values()}:
        raise ValueError('Expected canonical ordered feature contract')
    cohorts, settings = _load_cohorts(source, config, manifest)
    if set(cohorts) != {'original', 'corrected'}:
        raise ValueError('Expected original and corrected variants')
    for variant, cohort in cohorts.items():
        for partition in ('train', 'validation'):
            mask = cohort[partition]
            rows = [row for row, included in zip(cohort['records'], mask) if included]
            got = {'rows': len(rows), 'ordered_record_ids_sha256': _hash_object([r['record_id'] for r in rows]),
                   'labels_and_families_sha256': _hash_object([(r['binary_label'], r['source_label'], r['family']) for r in rows]),
                   'feature_matrix_sha256': hashlib.sha256(np.ascontiguousarray(cohort['matrix'][mask], dtype='<f8').tobytes()).hexdigest()}
            if provenance['cohorts'][variant][partition] != got:
                raise ValueError('Cohort fingerprint mismatch')
    params = {key: settings[key] for key in ('n_estimators', 'max_depth', 'min_samples_leaf', 'n_jobs')}
    params['random_state'] = settings['seed']
    if params != provenance.get('forest_settings') or settings['fpr_target'] != provenance['fpr_target'] or settings['alert_budget'] != provenance['alert_budget']:
        raise ValueError('Forest or threshold settings mismatch')
    metrics = _json(reference_dir / 'candidate_metrics.json')['candidates']['balanced_subsample']['variants']
    rows = {variant: [] for variant in cohorts}
    with (reference_dir / 'validation_predictions.csv').open(newline='', encoding='utf-8') as stream:
        for row in csv.DictReader(stream):
            if row['candidate'] == 'balanced_subsample':
                if row['variant'] not in rows:
                    raise ValueError('Unexpected reference variant')
                rows[row['variant']].append(row)
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='.freeze-binary-', dir=output.parent))
    try:
        summary = {}
        for variant, cohort in cohorts.items():
            pipeline = Pipeline([('preprocessing', 'passthrough'), ('classifier', RandomForestClassifier(**params, class_weight='balanced_subsample', max_features='sqrt'))])
            pipeline.fit(cohort['matrix'][cohort['train']], cohort['labels'][cohort['train']])
            threshold, count = _check_predictions(pipeline, cohort, settings, metrics[variant], rows[variant])
            model_dir = stage / variant
            model_dir.mkdir()
            bundle = {'schema_version': 1, 'bundle_type': 'binary_random_forest_v1', 'variant': variant, 'feature_allowlist': config['feature_allowlist'], 'feature_units': config['feature_units'], 'threshold': threshold, 'environment': environment_versions(), 'binary_pipeline': pipeline}
            joblib.dump(bundle, model_dir / 'bundle.joblib')
            metadata = {key: value for key, value in bundle.items() if key != 'binary_pipeline'}
            metadata['bundle_sha256'] = _sha(model_dir / 'bundle.joblib')
            _dump(model_dir / 'metadata.json', metadata)
            reloaded, _ = load_binary(model_dir)
            _check_predictions(reloaded['binary_pipeline'], cohort, settings, metrics[variant], rows[variant])
            summary[variant] = {'validation_rows_exact_before_and_after_reload': count, 'threshold': threshold, 'bundle_sha256': metadata['bundle_sha256']}
        if any(_sha(source / name) != digest for name, digest in source_hashes.items()) or any(_sha(reference_dir / name) != digest for name, digest in reference_hashes.items()):
            raise ValueError('Source or selected reference changed during freeze')
        _dump(stage / 'provenance.json', {'schema_version': 1, 'bundle_type': 'binary_random_forest_v1', 'source_run': str(source), 'source_files': source_hashes, 'reference_dir': str(reference_dir), 'reference_files': reference_hashes, 'cohorts': provenance['cohorts'], 'forest_settings': dict(params, class_weight='balanced_subsample', max_features='sqrt'), 'feature_allowlist': config['feature_allowlist'], 'feature_units': config['feature_units'], 'environment': environment_versions(), 'variants': summary, 'scope': 'Validation-only reproduction, no test scoring; trusted-local joblib only.'})
        stage.rename(output)
    except BaseException:
        shutil.rmtree(stage)
        raise
    return output
