"""Validation-only comparison of frozen versus expanded training cohorts."""
from collections import Counter
import csv
import math
from pathlib import Path
import shutil
import tempfile

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline

from .audit import _dump, _validate
from .evaluate import attack_scores, binary_metrics, select_threshold
from .feature_ablation import _cohort_hashes
from .model import environment_versions
from .prepare import FEATURES, selected_record
from .support_extract import feature_digest
from .tune import SOURCE_FILES, _csv, _json, _load_cohorts, _sha


ORDER = ('baseline', 'expanded')


def _load_supplement(directory, source, config, source_hashes):
    summary = _json(directory / 'summary.json')
    names = list(config['feature_allowlist'])
    if summary.get('status') != 'ok' or summary.get('schema_version') != 1 or summary.get('source_files') != source_hashes:
        raise ValueError('Supplement does not match frozen source')
    for name, key in [('supplement.csv', 'supplement_sha256'), ('exclusions.csv', 'exclusions_sha256')]:
        if _sha(directory / name) != summary.get(key):
            raise ValueError('Supplement file hash mismatch')
    datasets = {d['variant']: d for d in config['datasets']}
    if set(datasets) != set(summary.get('archive_sha256', {})):
        raise ValueError('Archive provenance does not cover variants')
    for variant, dataset in datasets.items():
        if dataset['preparation']['archive_sha256'] != summary['archive_sha256'][variant]:
            raise ValueError('Supplement archive provenance mismatch')
    blocked = {v: set() for v in datasets}
    for row in _csv(source / 'audit/splits.csv', ['variant', 'duplicate_group_id']):
        if row['variant'] not in blocked:
            raise ValueError('Unexpected frozen variant')
        if row['duplicate_group_id']:
            blocked[row['variant']].add(row['duplicate_group_id'])
    result = {v: [] for v in datasets}
    refs = set()
    fields = ['variant', 'origin_member', 'origin_record', 'source_label', 'family', 'binary_label', 'duplicate_group_id', *names]
    for row in _csv(directory / 'supplement.csv', fields, exact=fields):
        variant = row['variant']
        if variant not in datasets:
            raise ValueError('Unexpected supplement variant')
        dataset = datasets[variant]
        member, raw_ordinal = row['origin_member'], row['origin_record']
        if not Path(member).name.lower().startswith(('monday', 'tuesday')):
            raise ValueError('Supplement contains a non-training-day member')
        try:
            ordinal = int(raw_ordinal)
            values = [float(row[name]) for name in names]
        except ValueError as error:
            raise ValueError('Invalid supplement ordinal or feature') from error
        ref = (variant, member, ordinal)
        archive_hash = summary['archive_sha256'][variant]
        if ordinal < 2 or ref in refs or not selected_record(archive_hash, member, ordinal, 10) or selected_record(archive_hash, member, ordinal, 100):
            raise ValueError('Supplement identity or nested sampling mismatch')
        refs.add(ref)
        if not all(math.isfinite(x) for x in values) or values[0] < 0:
            raise ValueError('Invalid supplement values')
        digest = feature_digest(values)
        if digest != row['duplicate_group_id'] or digest in blocked[variant]:
            raise ValueError('Supplement duplicate or digest mismatch')
        blocked[variant].add(digest)
        label = row['source_label']
        mapping = dataset.get('label_map', config['label_map'])
        if label not in mapping or str(mapping[label]['binary']) != row['binary_label'] or mapping[label]['family'] != row['family']:
            raise ValueError('Supplement label mapping mismatch')
        result[variant].append((values, int(row['binary_label']), row['family']))
    for variant, rows in result.items():
        counts = summary['counts'][variant]
        if counts.get('retained', 0) != len(rows) or counts.get('retained_attack', 0) != sum(r[1] for r in rows) or counts.get('retained_benign', 0) != sum(not r[1] for r in rows):
            raise ValueError('Supplement support mismatch')
    return result, summary


def _select(candidates):
    reference = candidates['baseline']['variants']
    variants = set(reference)
    for entry in candidates.values():
        successful = bool(variants) and set(entry['variants']) == variants and all(v['status'] == 'ok' for v in entry['variants'].values())
        entry['eligible'] = successful and all(v['validation']['fpr'] <= v['threshold_policy']['fpr_target'] for v in entry['variants'].values())
        entry['mean_recall'] = float(np.mean([v['validation']['recall'] for v in entry['variants'].values()])) if successful else None
        entry['mean_fpr'] = float(np.mean([v['validation']['fpr'] for v in entry['variants'].values()])) if successful else None
    eligible = [name for name in ORDER if candidates[name]['eligible']]
    best = min(eligible, key=lambda name: (-candidates[name]['mean_recall'], candidates[name]['mean_fpr'], ORDER.index(name))) if eligible else None
    passed = bool(best == 'expanded' and candidates['baseline']['eligible'] and candidates['expanded']['mean_recall'] > candidates['baseline']['mean_recall'] + 1e-12 and all(candidates['expanded']['variants'][v]['validation']['recall'] >= reference[v]['validation']['recall'] - 1e-12 for v in variants))
    valid_reference = candidates['baseline']['eligible']
    return {'best_candidate': best, 'promoted_candidate': ('expanded' if passed else 'baseline') if valid_reference else None, 'status': 'ok' if valid_reference else 'failed_reference', 'promotion_passed': passed, 'tolerance': 1e-12, 'scope': 'Validation only; no test scoring.'}


def run_support_ablation(source_run, supplement_dir, output_dir):
    source, supplement_dir, output = map(lambda p: Path(p).resolve(), (source_run, supplement_dir, output_dir))
    if not source.is_dir() or not supplement_dir.is_dir() or output.exists() or output.is_relative_to(source) or output.is_relative_to(supplement_dir):
        raise ValueError('Expected frozen inputs and a fresh independent output')
    source_hashes = {name: _sha(source / name) for name in SOURCE_FILES}
    input_hashes = {name: _sha(supplement_dir / name) for name in ('summary.json', 'supplement.csv', 'exclusions.csv')}
    config, manifest = _json(source / 'config.json'), _json(source / 'manifest.json')
    _validate(config)
    if config['feature_allowlist'] != [v[0] for v in FEATURES.values()] or config['feature_units'] != {v[0]: v[1] for v in FEATURES.values()}:
        raise ValueError('Unexpected feature policy')
    cohorts, settings = _load_cohorts(source, config, manifest)
    supplement, extraction = _load_supplement(supplement_dir, source, config, source_hashes)
    params = {key: settings[key] for key in ('n_estimators', 'max_depth', 'min_samples_leaf', 'n_jobs')}
    params.update(random_state=settings['seed'], class_weight='balanced_subsample', max_features='sqrt')
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='.support-ablation-', dir=output.parent))
    try:
        candidates, predictions, per_family = {}, [], []
        for name in ORDER:
            entry = candidates[name] = {'variants': {}}
            for variant, cohort in cohorts.items():
                rows = supplement[variant] if name == 'expanded' else []
                train, valid = cohort['train'], cohort['validation']
                labels, records, matrix = cohort['labels'], cohort['records'], cohort['matrix']
                training_matrix = matrix[train]
                training_labels = labels[train]
                if rows:
                    training_matrix = np.vstack((training_matrix, np.array([r[0] for r in rows], dtype=float)))
                    training_labels = np.concatenate((training_labels, np.array([r[1] for r in rows], dtype=int)))
                families = Counter(r['family'] for r, included in zip(records, train) if included)
                families.update(r[2] for r in rows)
                support = {'benign': int(np.sum(training_labels == 0)), 'attack': int(np.sum(training_labels == 1))}
                try:
                    pipeline = Pipeline([('preprocessing', 'passthrough'), ('classifier', RandomForestClassifier(**params))])
                    pipeline.fit(training_matrix, training_labels)
                    scores = attack_scores(pipeline, matrix[valid])
                    policy = select_threshold(labels[valid], scores, settings['fpr_target'])
                    threshold = policy['threshold']
                    validation_rows = [r for r, included in zip(records, valid) if included]
                    metrics = binary_metrics(labels[valid], scores, threshold, [r['record_id'] for r in validation_rows], settings['alert_budget'])
                    policy['validation_metrics'] = metrics
                    metrics = dict(metrics, zero_score_benign=int(np.sum((scores == 0) & (labels[valid] == 0))), zero_score_attack=int(np.sum((scores == 0) & (labels[valid] == 1))))
                    for row, score in zip(validation_rows, scores):
                        predictions.append({'candidate': name, 'variant': variant, 'record_id': row['record_id'], 'partition': 'validation', 'source_label': row['source_label'], 'family': row['family'], 'binary_label': row['binary_label'], 'attack_score': float(score), 'threshold': threshold, 'prediction': int(score >= threshold)})
                    for family in sorted({r['family'] for r in validation_rows} | set(families)):
                        indices = [i for i, r in enumerate(validation_rows) if r['family'] == family]
                        per_family.append({'candidate': name, 'variant': variant, 'family': family, 'training_support': families[family], 'validation_support': len(indices), 'predicted_attack': sum(scores[i] >= threshold for i in indices)})
                    entry['variants'][variant] = {'status': 'ok', 'threshold_policy': policy, 'validation': metrics, 'training_support': support}
                except Exception as error:
                    entry['variants'][variant] = {'status': 'failed', 'error': f'{type(error).__name__}: {error}', 'training_support': support}
        selection = _select(candidates)
        for filename, fields, rows in [('validation_predictions.csv', ['candidate', 'variant', 'record_id', 'partition', 'source_label', 'family', 'binary_label', 'attack_score', 'threshold', 'prediction'], predictions), ('per_class_validation.csv', ['candidate', 'variant', 'family', 'training_support', 'validation_support', 'predicted_attack'], per_family)]:
            with (stage / filename).open('w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fields)
                writer.writeheader()
                writer.writerows(rows)
        _dump(stage / 'candidate_metrics.json', {'candidates': candidates, 'candidate_order': ORDER})
        _dump(stage / 'selection.json', selection)
        if any(_sha(source / name) != value for name, value in source_hashes.items()) or any(_sha(supplement_dir / name) != value for name, value in input_hashes.items()):
            raise ValueError('Source or supplement changed during experiment')
        _dump(stage / 'provenance.json', {'source_files': source_hashes, 'supplement_files': input_hashes, 'cohorts': _cohort_hashes(cohorts), 'forest_settings': params, 'environment': environment_versions(), 'supplement_counts': extraction['counts'], 'test_policy': 'Frozen test feature hashes used by extraction solely as transductive leakage guard; no test labels or predictions accessed.'})
        lines = ['# Training support ablation', '', 'Validation-only comparison using frozen 27-feature cohorts; no test scoring. Held-out feature hashes are a transductive leakage guard. Original clock uncertainty and temporal dependence remain.', '', '| Candidate | Variant | Status | Recall | FPR | Train benign | Train attacks |', '| --- | --- | --- | ---: | ---: | ---: | ---: |']
        for candidate, entry in candidates.items():
            for variant, value in entry['variants'].items():
                metrics = value.get('validation', {})
                support = value['training_support']
                lines.append(f"| {candidate} | {variant} | {value['status']} | {metrics.get('recall')} | {metrics.get('fpr')} | {support['benign']} | {support['attack']} |")
        lines.extend(['', f"Selected: {selection['promoted_candidate']}; promotion passed: {selection['promotion_passed']}.", 'This is repeated exploratory validation, not independent test evidence. No fitted bundles are saved.'])
        (stage / 'report.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
        stage.rename(output)
        return output
    except Exception:
        shutil.rmtree(stage)
        raise
