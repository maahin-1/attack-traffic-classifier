"""Calibrate pinned Experiment 006 models on the first CIC-DDoS2019 block."""
import hashlib
import json
import math
import sqlite3
import sys
import time
from pathlib import Path

import numpy as np
import joblib
import platform
import sklearn

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from attack_traffic.experiment007_input import iter_pinned_rows, sha256
from attack_traffic.evaluate import attack_scores
from attack_traffic.prepare import FEATURES

OUT = ROOT / 'artifacts/experiment-007-calibration'
AUDIT = ROOT / 'artifacts/experiment-007-quality-audit/report.json'
ADAPTER = ROOT / 'attack_traffic/experiment007_input.py'
MODELS = ROOT / 'artifacts/experiment-006-stage-b/models'
IDS = [f'experiment-006-{v}-{c}' for v in ('original', 'corrected') for c in ('reference', 'candidate')]


def write_json(path, obj):
    stage = path.with_suffix('.tmp')
    stage.write_text(json.dumps(obj, sort_keys=True, indent=2, allow_nan=False) + '\n', encoding='utf-8')
    stage.replace(path)


def choose(hist, benign, attacks):
    """Exact tied-score operating point; inputs sorted descending by score."""
    if benign <= 0 or attacks <= 0 or not hist:
        raise ValueError('Calibration requires both classes')
    best = (0, 0, math.nextafter(hist[0][0], math.inf))
    tp = fp = 0
    for score, b, a in hist:
        tp += a
        fp += b
        candidate = (tp, -(tp + fp), score)
        if fp * 100 <= benign and candidate > best:
            best = candidate
    return {'threshold': best[2], 'tp': best[0], 'fp': -best[1] - best[0],
            'benign': benign, 'attack': attacks, 'useful': best[0] > 0}


def main():
    audit = json.loads(AUDIT.read_text(encoding='utf-8'))
    if audit['status'] != 'complete' or audit['adapter_sha256'] != sha256(ADAPTER):
        raise ValueError('Completed audit or matching adapter required')
    models, model_hashes = {}, {}
    for name in IDS:
        directory = MODELS / name
        metadata = json.loads((directory / 'metadata.json').read_text(encoding='utf-8'))
        if sha256(directory / 'bundle.joblib') != metadata['bundle_sha256']:
            raise ValueError('Model bundle hash mismatch')
        if metadata['environment'] != {'python': platform.python_version(), 'numpy': np.__version__, 'scikit_learn': sklearn.__version__, 'joblib': joblib.__version__}:
            raise ValueError('Model environment mismatch')
        bundle = joblib.load(directory / 'bundle.joblib')
        if bundle.get('model_id') != name or bundle.get('feature_allowlist') != [v[0] for v in FEATURES.values()] or bundle.get('threshold') != metadata['threshold']:
            raise ValueError('Model identity or feature contract mismatch')
        models[name] = bundle['binary_model']
        model_hashes[name] = metadata['bundle_sha256']
    OUT.mkdir(parents=True, exist_ok=False)
    protocol = {'audit_sha256': sha256(AUDIT), 'adapter_sha256': sha256(ADAPTER),
                'runner_sha256': sha256(Path(__file__)), 'model_hashes': model_hashes,
                'calibration_archive': 'CSV-01-12.zip', 'assessment_archive': 'CSV-03-11.zip',
                'row_policy': 'retain all valid rows, including duplicate and conflicting feature groups',
                'invalid_policy': 'exclude and count invalid feature rows; fail on structural or label errors',
                'fpr_constraint': 'fp * 100 <= benign', 'comparison': 'score >= threshold',
                'tie_policy': 'maximize attack detections, then minimize alerts, then higher threshold',
                'assessment': 'no scoring until thresholds and hashes are frozen'}
    write_json(OUT / 'protocol.json', protocol)
    db = sqlite3.connect(OUT / 'score_histograms.sqlite')
    start = time.time()
    rows = valid = benign = attacks = 0
    errors = {}
    try:
        db.execute('CREATE TABLE hist(model TEXT, score REAL, benign INTEGER, attack INTEGER, PRIMARY KEY(model,score)) WITHOUT ROWID')
        batch_x, batch_y = [], []
        def flush():
            if not batch_x:
                return
            matrix, labels = np.asarray(batch_x, dtype=np.float64), np.asarray(batch_y, dtype=np.int8)
            for name, model in models.items():
                scores = attack_scores(model, matrix)
                unique, inverse = np.unique(scores, return_inverse=True)
                count = np.bincount(inverse)
                pos = np.bincount(inverse, weights=labels).astype(np.int64)
                db.executemany('INSERT INTO hist VALUES(?,?,?,?) ON CONFLICT(model,score) DO UPDATE SET benign=benign+excluded.benign, attack=attack+excluded.attack',
                               ((name, float(s), int(n-p), int(p)) for s, n, p in zip(unique, count, pos)))
            db.commit()
            batch_x.clear(); batch_y.clear()
        for record in iter_pinned_rows(ROOT / 'data/cicddos2019', 'calibration'):
            rows += 1
            if 'error' in record:
                errors[record['error']] = errors.get(record['error'], 0) + 1
                continue
            valid += 1
            benign += record['label'] == 0
            attacks += record['label'] == 1
            batch_x.append(record['features']); batch_y.append(record['label'])
            if len(batch_x) == 20000:
                flush()
                write_json(OUT / 'progress.json', {'status': 'running', 'rows': rows, 'valid': valid, 'elapsed_seconds': round(time.time()-start, 1)})
        flush()
        expected = audit['roles']['calibration']
        if rows != expected['rows'] or valid != expected['valid'] or errors != expected['errors']:
            raise ValueError('Calibration counts differ from completed quality audit')
        thresholds = {}
        for name in IDS:
            hist = list(db.execute('SELECT score,benign,attack FROM hist WHERE model=? ORDER BY score DESC', (name,)))
            if sum(x[1] for x in hist) != benign or sum(x[2] for x in hist) != attacks:
                raise ValueError('Score histogram support mismatch')
            thresholds[name] = choose(hist, benign, attacks)
        if sha256(ADAPTER) != protocol['adapter_sha256'] or sha256(Path(__file__)) != protocol['runner_sha256'] or sha256(AUDIT) != protocol['audit_sha256']:
            raise ValueError('Frozen input changed during calibration')
        for name in IDS:
            if sha256(MODELS / name / 'bundle.joblib') != model_hashes[name]:
                raise ValueError('Model changed during calibration')
        result = {'status': 'frozen', 'protocol_sha256': sha256(OUT / 'protocol.json'), 'rows': rows,
                  'valid': valid, 'errors': errors, 'thresholds': thresholds, 'elapsed_seconds': round(time.time()-start, 1)}
        write_json(OUT / 'thresholds.json', result)
        write_json(OUT / 'progress.json', result)
    except BaseException as exc:
        write_json(OUT / 'progress.json', {'status': 'failed', 'rows': rows, 'valid': valid, 'error': repr(exc)})
        raise
    finally:
        db.close()


if __name__ == '__main__':
    main()
