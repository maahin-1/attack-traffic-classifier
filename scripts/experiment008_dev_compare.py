"""Corrected CICIDS2017 source-specific feature comparison, development only.

Wednesday selects thresholds and reports development metrics: no protected test
or 2019 capture is read, and no production model artifacts are generated.
"""
import csv
import hashlib
import io
import json
import math
import platform
import sys
import time
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import RandomForestClassifier

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from attack_traffic.evaluate import attack_scores, binary_metrics, select_threshold
from attack_traffic.experiment007_input import sha256
from attack_traffic.prepare import FEATURES
from scripts.feature_feasibility_008 import FLAGS

ARCHIVE = ROOT / 'data/cns2022/CICIDS2017_improved.zip'
FOLDER = ROOT / 'data/cns2022/subset-1pct-capture-date'
OUT = ROOT / 'artifacts/experiment-008-dev-comparison'
NAMES = [v[0] for v in FEATURES.values()]
FIT = {'n_estimators': 200, 'max_depth': 12, 'min_samples_leaf': 2, 'max_features': 'sqrt', 'class_weight': None, 'random_state': 42, 'n_jobs': 1}
MODES = {'baseline': (), 'protocol': (0,), 'flags': tuple(range(1, 8)), 'protocol_and_flags': tuple(range(8))}


def dump(path, data):
    stage = path.with_suffix('.tmp')
    stage.write_text(json.dumps(data, indent=2, sort_keys=True, allow_nan=False) + '\n', encoding='utf-8')
    stage.replace(path)


def split_development(rows):
    """Preserve first baseline-vector representative and block cross-day matches."""
    early = sorted((r for r in rows if r['date'] in ('2017-07-03', '2017-07-04')), key=lambda r: (r['date'], r['member'], r['record']))
    later = sorted((r for r in rows if r['date'] == '2017-07-05'), key=lambda r: (r['date'], r['member'], r['record']))
    seen = set()
    train = []
    for row in early:
        if row['base'] not in seen:
            seen.add(row['base']); train.append(row)
    validation = []
    for row in later:
        if row['base'] not in seen:
            seen.add(row['base']); validation.append(row)
    return train, validation, {'train_input': len(early), 'train_dropped': len(early)-len(train),
                               'validation_input': len(later), 'validation_dropped': len(later)-len(validation)}


def load_corrected():
    config = json.loads((FOLDER / 'config.json').read_text(encoding='utf-8'))
    dataset = config['datasets'][0]
    mapping = dataset.get('label_map', config.get('label_map', {}))
    targets = defaultdict(dict)
    invalid_base = 0
    with (FOLDER / 'flows.csv').open(encoding='utf-8-sig', newline='') as stream:
        for row in csv.DictReader(stream):
            if row['capture_date'] not in {'2017-07-03', '2017-07-04', '2017-07-05'}:
                continue
            values = tuple(float(row[n]) for n in NAMES)
            if not all(math.isfinite(v) for v in values) or values[0] < 0:
                invalid_base += 1
                continue
            label = mapping.get(row['source_label'])
            if not label or label.get('binary') not in (0, 1):
                raise ValueError('Unknown source label')
            record = int(row['origin_record'])
            if record in targets[row['origin_member']]:
                raise ValueError('Duplicate source reference')
            targets[row['origin_member']][record] = {'base': values, 'label': int(label['binary']), 'family': str(label['family']),
                'source_label': row['source_label'], 'date': row['capture_date'], 'member': row['origin_member'], 'record': record}
    rows, invalid_extra = [], 0
    with zipfile.ZipFile(ARCHIVE) as bundle:
        for member, pending in sorted(targets.items()):
            with bundle.open(member) as raw, io.TextIOWrapper(raw, encoding='utf-8-sig', newline='') as stream:
                reader = csv.reader(stream)
                headers = [h.strip().lstrip('\ufeff') for h in next(reader)]
                required = list(FEATURES) + ['Label', 'Protocol', *FLAGS]
                if any(headers.count(name) != 1 for name in required):
                    raise ValueError(f'Missing or ambiguous columns: {member}')
                base_i = [headers.index(name) for name in FEATURES]
                extra_i = [headers.index(name) for name in ('Protocol', *FLAGS)]
                label_i = headers.index('Label')
                for number, data in enumerate(reader, 2):
                    if number not in pending:
                        continue
                    row = pending.pop(number)
                    if len(data) != len(headers) or data[label_i].strip() != row['source_label']:
                        raise ValueError(f'Source label/width mismatch {member}:{number}')
                    if tuple(float(data[i]) for i in base_i) != row['base']:
                        raise ValueError(f'Source feature mismatch {member}:{number}')
                    try:
                        extra = tuple(float(data[i]) for i in extra_i)
                    except ValueError:
                        invalid_extra += 1
                        continue
                    if not all(math.isfinite(x) and x >= 0 and x.is_integer() for x in extra) or extra[0] > 255:
                        invalid_extra += 1
                        continue
                    row['extra'] = extra
                    row['id'] = f'{member}:{number}'
                    rows.append(row)
                    if not pending:
                        break
            if pending:
                raise ValueError(f'Source references missing in {member}: {len(pending)}')
    return rows, {'invalid_base': invalid_base, 'invalid_extra': invalid_extra}


def family_metrics(rows, labels, scores, threshold):
    stats = defaultdict(lambda: {'support': 0, 'detected': 0})
    for row, label, score in zip(rows, labels, scores):
        if label == 1:
            stats[row['family']]['support'] += 1
            stats[row['family']]['detected'] += int(score >= threshold)
    return {name: {**entry, 'recall': entry['detected'] / entry['support']} for name, entry in sorted(stats.items())}


def main():
    source_files = [ARCHIVE, FOLDER / 'flows.csv', FOLDER / 'config.json', FOLDER / 'preparation.json', Path(__file__),
                    ROOT / 'attack_traffic/prepare.py', ROOT / 'attack_traffic/evaluate.py', ROOT / 'scripts/feature_feasibility_008.py']
    hashes = {p.relative_to(ROOT).as_posix(): sha256(p) for p in source_files}
    acquisition = json.loads((ROOT / 'data/cns2022/acquisition.json').read_text(encoding='utf-8'))
    if hashes[ARCHIVE.relative_to(ROOT).as_posix()] != acquisition['sha256']:
        raise ValueError('Corrected archive differs from acquired source')
    stage_b = json.loads((ROOT / 'artifacts/experiment-006-stage-b/manifest.json').read_text(encoding='utf-8'))
    for name in ('flows.csv', 'config.json', 'preparation.json'):
        relative = (FOLDER / name).relative_to(ROOT)
        key = str(relative)
        if stage_b['input_sha256'].get(key) != hashes[relative.as_posix()]:
            raise ValueError(f'Development sample differs from experiment 006: {name}')
    OUT.mkdir(parents=True, exist_ok=False)
    protocol = {'scope': 'corrected CICIDS2017 only; development comparison; no 2019/Thursday/Friday',
        'dates': {'train': ['2017-07-03', '2017-07-04'], 'validation_and_threshold_selection': ['2017-07-05']},
        'group_policy': 'unique first baseline 27-vector per training and validation, block training groups from Wednesday; identical rows in all arms',
        'fields': {'base': NAMES, 'protocol': ['Protocol'], 'flags': list(FLAGS)}, 'modes': {key:list(v) for key,v in MODES.items()},
        'training': FIT, 'threshold_rule': 'maximize Wednesday attack recall subject to observed benign FPR <= 1%, ties favor fewer alerts and higher threshold',
        'caveat': 'Wednesday is used to select threshold and calculate metrics; results optimistic and not independent; prior experiment and assessment informed feature choices',
        'extraction': 'source-specific corrected flag counts; no claim of equivalence to original 2017 or DDoS2019',
        'input_sha256': hashes, 'environment': {'python': platform.python_version(), 'numpy': np.__version__, 'scikit_learn': sklearn.__version__, 'joblib': joblib.__version__}}
    dump(OUT / 'protocol.json', protocol)
    started = time.time()
    rows, exclusions = load_corrected()
    train, validation, group_counts = split_development(rows)
    y_train = np.array([r['label'] for r in train], dtype=int)
    y_valid = np.array([r['label'] for r in validation], dtype=int)
    if set(y_train) != {0, 1} or set(y_valid) != {0, 1}:
        raise ValueError('Train and validation each require benign and attack rows')
    ids = [r['id'] for r in validation]
    results = {}
    for name, extras in MODES.items():
        x_train = np.asarray([r['base'] + tuple(r['extra'][i] for i in extras) for r in train], dtype=float)
        x_valid = np.asarray([r['base'] + tuple(r['extra'][i] for i in extras) for r in validation], dtype=float)
        model = RandomForestClassifier(**FIT).fit(x_train, y_train)
        scores = attack_scores(model, x_valid)
        selected = select_threshold(y_valid, scores, 0.01)
        cutoff = selected['threshold']
        metrics = binary_metrics(y_valid, scores, cutoff, ids)
        fixed = binary_metrics(y_valid, scores, 0.5, ids)
        results[name] = {'feature_count': x_train.shape[1], 'selected_threshold': cutoff,
                         'selected_threshold_useful': selected['useful'], 'development_metrics': metrics,
                         'fixed_0_5_metrics': fixed, 'family_recall': family_metrics(validation, y_valid, scores, cutoff)}
    for path, digest in hashes.items():
        if sha256(ROOT / path) != digest:
            raise ValueError(f'Input changed during run: {path}')
    summary = {'status': 'complete', 'protocol_sha256': sha256(OUT / 'protocol.json'), 'source_exclusions': exclusions,
        'group_split': group_counts, 'train_support': dict(Counter('attack' if x else 'benign' for x in y_train)),
        'validation_support': dict(Counter('attack' if x else 'benign' for x in y_valid)),
        'train_ids_sha256': hashlib.sha256('\n'.join(r['id'] for r in train).encode()).hexdigest(),
        'validation_ids_sha256': hashlib.sha256('\n'.join(ids).encode()).hexdigest(),
        'results': results, 'elapsed_seconds': round(time.time()-started, 1)}
    dump(OUT / 'report.json', summary)
    print(json.dumps({'status': summary['status'], 'train': summary['train_support'], 'validation': summary['validation_support'], 'elapsed_seconds': summary['elapsed_seconds']}))


if __name__ == '__main__':
    main()
