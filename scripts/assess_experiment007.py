"""One frozen-threshold assessment on the pinned second CIC-DDoS2019 archive."""
import json
import platform
import sqlite3
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import sklearn

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from attack_traffic.experiment007_input import iter_pinned_rows, sha256
from attack_traffic.evaluate import attack_scores
from attack_traffic.prepare import FEATURES

CAL = ROOT / 'artifacts/experiment-007-calibration'
AUDIT = ROOT / 'artifacts/experiment-007-quality-audit/report.json'
ADAPTER = ROOT / 'attack_traffic/experiment007_input.py'
MODELS = ROOT / 'artifacts/experiment-006-stage-b/models'
OUT = ROOT / 'artifacts/experiment-007-assessment'


def write_json(path, obj):
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(obj, indent=2, sort_keys=True, allow_nan=False) + '\n', encoding='utf-8')
    tmp.replace(path)


def summarize(tp, fp, tn, fn):
    return {'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
            'fpr': fp / (fp + tn) if fp + tn else None,
            'recall': tp / (tp + fn) if tp + fn else None,
            'precision': tp / (tp + fp) if tp + fp else None}


def distribution(hist):
    total = sum(n for _, n in hist)
    if not total:
        return {'support': 0, 'zero_scores': 0, 'quantiles': {}}
    targets = {str(q): max(1, int(np.ceil(q * total))) for q in (0.5, 0.9, 0.99)}
    quantiles, seen = {}, 0
    for score, count in hist:
        seen += count
        for label, target in targets.items():
            if label not in quantiles and seen >= target:
                quantiles[label] = score
    return {'support': total, 'zero_scores': sum(n for score, n in hist if score == 0), 'quantiles': quantiles}


def main():
    frozen = json.loads((CAL / 'thresholds.json').read_text(encoding='utf-8'))
    protocol = json.loads((CAL / 'protocol.json').read_text(encoding='utf-8'))
    audit = json.loads(AUDIT.read_text(encoding='utf-8'))
    if frozen['status'] != 'frozen' or frozen['protocol_sha256'] != sha256(CAL / 'protocol.json'):
        raise ValueError('Calibration threshold freeze is missing or inconsistent')
    if sha256(ADAPTER) != protocol['adapter_sha256'] or sha256(AUDIT) != protocol['audit_sha256']:
        raise ValueError('Adapter or quality audit differs from the frozen protocol')
    models = {}
    for name, digest in protocol['model_hashes'].items():
        directory = MODELS / name
        metadata = json.loads((directory / 'metadata.json').read_text(encoding='utf-8'))
        if sha256(directory / 'bundle.joblib') != digest or metadata['bundle_sha256'] != digest:
            raise ValueError('Model bundle hash mismatch')
        if metadata['environment'] != {'python': platform.python_version(), 'numpy': np.__version__, 'scikit_learn': sklearn.__version__, 'joblib': joblib.__version__}:
            raise ValueError('Model environment mismatch')
        bundle = joblib.load(directory / 'bundle.joblib')
        if bundle.get('model_id') != name or bundle.get('feature_allowlist') != [v[0] for v in FEATURES.values()] or bundle.get('threshold') != metadata['threshold']:
            raise ValueError('Model contract mismatch')
        models[name] = (bundle['binary_model'], float(frozen['thresholds'][name]['threshold']), float(bundle['threshold']))
    if set(models) != set(frozen['thresholds']):
        raise ValueError('Threshold and model sets differ')
    OUT.mkdir(parents=True, exist_ok=False)
    start = time.time()
    frozen_hash = sha256(CAL / 'thresholds.json')
    write_json(OUT / 'protocol.json', {'thresholds_sha256': frozen_hash, 'calibration_protocol_sha256': frozen['protocol_sha256'],
        'audit_sha256': protocol['audit_sha256'], 'adapter_sha256': protocol['adapter_sha256'],
        'runner_sha256': sha256(Path(__file__)), 'model_hashes': protocol['model_hashes'],
        'assessment_archive': 'CSV-03-11.zip', 'policy': 'retain all valid rows; report both frozen calibration and original thresholds'})
    db = sqlite3.connect(OUT / 'score_histograms.sqlite')
    rows = valid = 0
    errors = {}
    try:
        db.execute('CREATE TABLE hist(model TEXT, family TEXT, score REAL, n INTEGER, PRIMARY KEY(model,family,score)) WITHOUT ROWID')
        batch_x, batch_family = [], []
        def flush():
            if not batch_x:
                return
            matrix = np.asarray(batch_x, dtype=np.float64)
            families = np.asarray(batch_family)
            for name, (model, _, _) in models.items():
                scores = attack_scores(model, matrix)
                for family in np.unique(families):
                    values, counts = np.unique(scores[families == family], return_counts=True)
                    db.executemany('INSERT INTO hist VALUES(?,?,?,?) ON CONFLICT(model,family,score) DO UPDATE SET n=n+excluded.n',
                        ((name, str(family), float(score), int(count)) for score, count in zip(values, counts)))
            db.commit()
            batch_x.clear(); batch_family.clear()
        for record in iter_pinned_rows(ROOT / 'data/cicddos2019', 'assessment'):
            rows += 1
            if 'error' in record:
                errors[record['error']] = errors.get(record['error'], 0) + 1
                continue
            valid += 1
            batch_x.append(record['features']); batch_family.append(record['family'])
            if len(batch_x) == 20000:
                flush()
                write_json(OUT / 'progress.json', {'status': 'running', 'rows': rows, 'valid': valid, 'elapsed_seconds': round(time.time()-start, 1)})
        flush()
        expected = audit['roles']['assessment']
        if (rows, valid, errors) != (expected['rows'], expected['valid'], expected['errors']):
            raise ValueError('Assessment counts differ from quality audit')
        results = {}
        for name, (_, threshold, old_threshold) in models.items():
            by_threshold = {}
            for label, cutoff in (('recalibrated', threshold), ('experiment006', old_threshold)):
                families = {}
                tp = fp = tn = fn = 0
                for family, positive, negative in db.execute('SELECT family, SUM(CASE WHEN score>=? THEN n ELSE 0 END), SUM(CASE WHEN score<? THEN n ELSE 0 END) FROM hist WHERE model=? GROUP BY family', (cutoff, cutoff, name)):
                    families[family] = {'support': positive + negative, 'detected': positive, 'detection_rate': positive/(positive+negative)}
                    if family == 'BENIGN': fp, tn = positive, negative
                    else: tp += positive; fn += negative
                by_threshold[label] = {'threshold': cutoff, 'metrics': summarize(tp, fp, tn, fn), 'families': families}
            distributions = {}
            for kind, condition in (('benign', 'family = ?'), ('attack', 'family != ?')):
                hist = list(db.execute('SELECT score, SUM(n) FROM hist WHERE model=? AND ' + condition + ' GROUP BY score ORDER BY score', (name, 'BENIGN')))
                distributions[kind] = distribution(hist)
            results[name] = {'thresholds': by_threshold, 'score_distributions': distributions}
        if sha256(CAL / 'thresholds.json') != frozen_hash or sha256(ADAPTER) != protocol['adapter_sha256'] or sha256(AUDIT) != protocol['audit_sha256']:
            raise ValueError('Frozen inputs changed during assessment')
        for name, digest in protocol['model_hashes'].items():
            if sha256(MODELS / name / 'bundle.joblib') != digest:
                raise ValueError('Model changed during assessment')
        result = {'status': 'complete', 'rows': rows, 'valid': valid, 'errors': errors, 'results': results,
                  'collision_audit': audit['collisions'], 'thresholds_sha256': frozen_hash,
                  'elapsed_seconds': round(time.time()-start, 1)}
        write_json(OUT / 'report.json', result)
        write_json(OUT / 'progress.json', result)
    except BaseException as exc:
        write_json(OUT / 'progress.json', {'status': 'failed', 'rows': rows, 'valid': valid, 'error': repr(exc)})
        raise
    finally:
        db.close()


if __name__ == '__main__':
    main()
