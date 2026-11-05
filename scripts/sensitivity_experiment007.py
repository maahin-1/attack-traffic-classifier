"""Post-assessment descriptive group and conflicting-label sensitivity analysis."""
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
from attack_traffic.evaluate import attack_scores
from attack_traffic.experiment007_input import iter_pinned_rows, sha256
from attack_traffic.prepare import FEATURES
from attack_traffic.support_extract import feature_digest
from scripts.assess_experiment007 import summarize, write_json

CAL = ROOT / 'artifacts/experiment-007-calibration'
AUDIT = ROOT / 'artifacts/experiment-007-quality-audit'
ASSESS = ROOT / 'artifacts/experiment-007-assessment/report.json'
ADAPTER = ROOT / 'attack_traffic/experiment007_input.py'
MODELS = ROOT / 'artifacts/experiment-006-stage-b/models'
PLAN = ROOT / 'docs/EXPERIMENT-007-SENSITIVITY-PLAN.md'
OUT = ROOT / 'artifacts/experiment-007-sensitivity'


def add_counts(counts, labels, predictions, weights):
    for key, mask in (('tp', (labels == 1) & predictions), ('fn', (labels == 1) & ~predictions),
                      ('fp', (labels == 0) & predictions), ('tn', (labels == 0) & ~predictions)):
        counts[key] += int(weights[mask].sum())


def main():
    frozen = json.loads((CAL / 'thresholds.json').read_text(encoding='utf-8'))
    protocol = json.loads((CAL / 'protocol.json').read_text(encoding='utf-8'))
    audit = json.loads((AUDIT / 'report.json').read_text(encoding='utf-8'))
    original = json.loads(ASSESS.read_text(encoding='utf-8'))
    if (frozen['status'] != 'frozen' or original['status'] != 'complete' or audit['status'] != 'complete'
            or frozen['protocol_sha256'] != sha256(CAL / 'protocol.json')
            or original['thresholds_sha256'] != sha256(CAL / 'thresholds.json')
            or protocol['adapter_sha256'] != sha256(ADAPTER) or protocol['audit_sha256'] != sha256(AUDIT / 'report.json')):
        raise ValueError('Frozen assessment inputs do not match')
    models = {}
    for name, digest in protocol['model_hashes'].items():
        directory = MODELS / name
        metadata = json.loads((directory / 'metadata.json').read_text(encoding='utf-8'))
        if sha256(directory / 'bundle.joblib') != digest or metadata['bundle_sha256'] != digest:
            raise ValueError('Model hash mismatch')
        if metadata['environment'] != {'python': platform.python_version(), 'numpy': np.__version__, 'scikit_learn': sklearn.__version__, 'joblib': joblib.__version__}:
            raise ValueError('Model environment mismatch')
        bundle = joblib.load(directory / 'bundle.joblib')
        if bundle.get('model_id') != name or bundle.get('feature_allowlist') != [v[0] for v in FEATURES.values()] or bundle.get('threshold') != metadata['threshold']:
            raise ValueError('Model contract mismatch')
        models[name] = (bundle['binary_model'], {'recalibrated': float(frozen['thresholds'][name]['threshold']), 'experiment006': float(bundle['threshold'])})
    if set(models) != set(frozen['thresholds']) or set(models) != set(original['results']):
        raise ValueError('Model sets differ')
    db_path = AUDIT / 'groups.sqlite'
    db_hash = sha256(db_path)
    source = sqlite3.connect(db_path.as_uri() + '?mode=ro', uri=True)
    totals = source.execute('SELECT count(*), sum(cb+ca+ab+aa), sum(CASE WHEN cb+ab>0 AND ca+aa>0 THEN 1 ELSE 0 END) FROM groups').fetchone()
    if totals != (audit['collisions']['unique_groups'], audit['collisions']['valid_rows'], audit['collisions']['binary_conflict_groups']):
        raise ValueError('Audit database does not match the completed audit')
    OUT.mkdir(parents=True, exist_ok=False)
    fingerprint = {'plan_sha256': sha256(PLAN), 'runner_sha256': sha256(Path(__file__)), 'audit_db_sha256': db_hash,
                   'audit_report_sha256': sha256(AUDIT / 'report.json'), 'adapter_sha256': sha256(ADAPTER),
                   'thresholds_sha256': sha256(CAL / 'thresholds.json'), 'assessment_report_sha256': sha256(ASSESS),
                   'model_hashes': protocol['model_hashes']}
    write_json(OUT / 'protocol.json', fingerprint)
    seen = sqlite3.connect(OUT / 'seen.sqlite')
    start = time.time()
    rows = valid = pairs = weighted_rows = excluded_rows = 0
    errors = {}
    metrics = {name: {t: {mode: dict.fromkeys(('tp', 'fp', 'tn', 'fn'), 0) for mode in ('row_weighted', 'group_label_weighted', 'conflict_excluded')} for t in thresholds} for name, (_, thresholds) in models.items()}
    try:
        seen.execute('CREATE TABLE seen (digest BLOB, label INTEGER, PRIMARY KEY(digest,label)) WITHOUT ROWID')
        batch_x, batch_y, batch_weight, batch_conflict = [], [], [], []
        def flush():
            if batch_x:
                x, y = np.asarray(batch_x, dtype=np.float64), np.asarray(batch_y, dtype=np.int8)
                weights = np.asarray(batch_weight, dtype=np.int64)
                conflict = np.asarray(batch_conflict, dtype=bool)
                for name, (model, thresholds) in models.items():
                    scores = attack_scores(model, x)
                    for label, threshold in thresholds.items():
                        predicted = scores >= threshold
                        add_counts(metrics[name][label]['row_weighted'], y, predicted, weights)
                        add_counts(metrics[name][label]['group_label_weighted'], y, predicted, np.ones(len(y), dtype=np.int64))
                        add_counts(metrics[name][label]['conflict_excluded'], y, predicted, weights * (~conflict))
                batch_x.clear(); batch_y.clear(); batch_weight.clear(); batch_conflict.clear()
            seen.commit()
        for record in iter_pinned_rows(ROOT / 'data/cicddos2019', 'assessment'):
            rows += 1
            if 'error' in record:
                errors[record['error']] = errors.get(record['error'], 0) + 1
            else:
                valid += 1
                digest = bytes.fromhex(feature_digest(record['features']))
                label = record['label']
                inserted = seen.execute('INSERT OR IGNORE INTO seen VALUES (?,?)', (digest, label)).rowcount
                if inserted:
                    group = source.execute('SELECT cb,ca,ab,aa FROM groups WHERE digest=?', (digest,)).fetchone()
                    if group is None:
                        raise ValueError('Feature digest is absent from audit')
                    cb, ca, ab, aa = group
                    weight = (ab, aa)[label]
                    if weight <= 0:
                        raise ValueError('Assessment label absent from audit group')
                    conflict = cb + ab > 0 and ca + aa > 0
                    pairs += 1; weighted_rows += weight
                    excluded_rows += weight if conflict else 0
                    batch_x.append(record['features']); batch_y.append(label); batch_weight.append(weight); batch_conflict.append(conflict)
                    if len(batch_x) >= 10000:
                        flush()
            if rows % 100000 == 0:
                flush()
                write_json(OUT / 'progress.json', {'status': 'running', 'rows': rows, 'valid': valid, 'group_label_pairs': pairs, 'elapsed_seconds': round(time.time()-start, 1)})
        flush()
        expected = audit['roles']['assessment']
        if (rows, valid, errors, weighted_rows) != (expected['rows'], expected['valid'], expected['errors'], valid):
            raise ValueError('Source or group-weight totals do not match audit')
        for name in models:
            for threshold in models[name][1]:
                actual = metrics[name][threshold]['row_weighted']
                existing = original['results'][name]['thresholds'][threshold]['metrics']
                if any(actual[k] != existing[k] for k in actual):
                    raise ValueError(f'Original confusion counts do not reproduce for {name} {threshold}')
                for mode, counts in metrics[name][threshold].items():
                    metrics[name][threshold][mode] = summarize(counts['tp'], counts['fp'], counts['tn'], counts['fn'])
        for path, key in ((PLAN, 'plan_sha256'), (Path(__file__), 'runner_sha256'), (db_path, 'audit_db_sha256'),
                          (AUDIT / 'report.json', 'audit_report_sha256'), (ADAPTER, 'adapter_sha256'),
                          (CAL / 'thresholds.json', 'thresholds_sha256'), (ASSESS, 'assessment_report_sha256')):
            if sha256(path) != fingerprint[key]:
                raise ValueError(f'Frozen input changed during analysis: {path.name}')
        for name, digest in protocol['model_hashes'].items():
            if sha256(MODELS / name / 'bundle.joblib') != digest:
                raise ValueError('Model changed during analysis')
        result = {'status': 'complete', 'rows': rows, 'valid': valid, 'errors': errors, 'group_label_pairs': pairs,
                  'conflict_excluded_rows': excluded_rows, 'original_confusion_reproduced': True,
                  'protocol_sha256': sha256(OUT / 'protocol.json'), 'results': metrics, 'elapsed_seconds': round(time.time()-start, 1)}
        write_json(OUT / 'report.json', result); write_json(OUT / 'progress.json', result)
    except BaseException as exc:
        write_json(OUT / 'progress.json', {'status': 'failed', 'rows': rows, 'valid': valid, 'error': repr(exc)})
        raise
    finally:
        source.close(); seen.close()


if __name__ == '__main__':
    main()
