"""Trace high-volume Experiment 007 feature groups to assessment CSV context."""
import csv
import io
import json
import platform
import sqlite3
import sys
import time
import zipfile
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
import sklearn

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from attack_traffic.evaluate import attack_scores
from attack_traffic.experiment007_input import ALIASES, ARCHIVES, FAMILIES, sha256
from attack_traffic.prepare import FEATURES
from attack_traffic.support_extract import feature_digest
from scripts.assess_experiment007 import write_json

AUDIT = ROOT / 'artifacts/experiment-007-quality-audit'
CAL = ROOT / 'artifacts/experiment-007-calibration'
MODELS = ROOT / 'artifacts/experiment-006-stage-b/models'
ADAPTER = ROOT / 'attack_traffic/experiment007_input.py'
OUT = ROOT / 'artifacts/experiment-007-group-investigation'


def update_context(group, label, member, timestamp, protocol, port, line):
    group['labels'][label] += 1
    group['members'][member] += 1
    group['protocols'][protocol] += 1
    group['destination_ports'][port] += 1
    context = group['by_label'].setdefault(label, {'rows': 0, 'first_timestamp': timestamp, 'last_timestamp': timestamp,
                                                  'example': {'member': member, 'line': line, 'timestamp': timestamp, 'protocol': protocol, 'destination_port': port}})
    context['rows'] += 1
    context['first_timestamp'] = min(context['first_timestamp'], timestamp)
    context['last_timestamp'] = max(context['last_timestamp'], timestamp)


def main():
    audit = json.loads((AUDIT / 'report.json').read_text(encoding='utf-8'))
    frozen = json.loads((CAL / 'thresholds.json').read_text(encoding='utf-8'))
    protocol = json.loads((CAL / 'protocol.json').read_text(encoding='utf-8'))
    if audit['status'] != 'complete' or frozen['status'] != 'frozen' or frozen['protocol_sha256'] != sha256(CAL / 'protocol.json'):
        raise ValueError('Completed audit and frozen calibration required')
    if protocol['audit_sha256'] != sha256(AUDIT / 'report.json') or protocol['adapter_sha256'] != sha256(ADAPTER):
        raise ValueError('Audit or adapter hash mismatch')
    archive = ROOT / 'data/cicddos2019' / ARCHIVES['assessment'][0]
    if sha256(archive) != ARCHIVES['assessment'][1]:
        raise ValueError('Assessment archive hash mismatch')
    source = sqlite3.connect((AUDIT / 'groups.sqlite').as_uri() + '?mode=ro', uri=True)
    try:
        top = source.execute('SELECT hex(digest),cb,ca,ab,aa FROM groups WHERE aa>0 ORDER BY aa DESC, digest LIMIT 5').fetchall()
        conflicts = source.execute('SELECT hex(digest),cb,ca,ab,aa FROM groups WHERE cb+ab>0 AND ca+aa>0 AND ab+aa>0 ORDER BY ab+aa DESC, digest LIMIT 5').fetchall()
    finally:
        source.close()
    selected = {}
    for reason, records in (('largest_assessment_attack_groups', top), ('largest_assessment_conflicting_groups', conflicts)):
        for digest, cb, ca, ab, aa in records:
            item = selected.setdefault(digest.lower(), {'audit_counts': {'calibration_benign': cb, 'calibration_attack': ca, 'assessment_benign': ab, 'assessment_attack': aa}, 'selection': []})
            item['selection'].append(reason)
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
        models[name] = (bundle['binary_model'], float(bundle['threshold']), float(frozen['thresholds'][name]['threshold']))
    OUT.mkdir(parents=True, exist_ok=False)
    fingerprint = {'source_sha256': ARCHIVES['assessment'][1], 'audit_report_sha256': sha256(AUDIT / 'report.json'),
                   'audit_db_sha256': sha256(AUDIT / 'groups.sqlite'), 'adapter_sha256': sha256(ADAPTER),
                   'thresholds_sha256': sha256(CAL / 'thresholds.json'), 'runner_sha256': sha256(Path(__file__)),
                   'model_hashes': protocol['model_hashes'], 'selection': 'top five assessment attack groups and top five conflicting groups by assessment row count; ties by digest',
                   'scope': 'descriptive, selected after assessment; aggregate source context without endpoint addresses', 'selected': selected}
    write_json(OUT / 'protocol.json', fingerprint)
    groups = {key: {'labels': Counter(), 'members': Counter(), 'protocols': Counter(), 'destination_ports': Counter(), 'by_label': {}, 'features': None} for key in selected}
    rows = 0
    start = time.time()
    try:
        with zipfile.ZipFile(archive) as bundle:
            members = sorted((x for x in bundle.infolist() if not x.is_dir() and x.filename.lower().endswith('.csv')), key=lambda x: x.filename)
            for member in members:
                with bundle.open(member) as raw, io.TextIOWrapper(raw, encoding='utf-8-sig', newline='') as text:
                    reader = csv.reader(text)
                    headers = [x.strip() for x in next(reader)]
                    if len(headers) != 88 or len(set(headers)) != 88:
                        raise ValueError(f'Unexpected header: {member.filename}')
                    feature_indices = [headers.index(ALIASES.get(name, name)) for name in FEATURES]
                    label_i, time_i, proto_i, port_i = (headers.index(x) for x in ('Label', 'Timestamp', 'Protocol', 'Destination Port'))
                    for line, row in enumerate(reader, 2):
                        rows += 1
                        if len(row) != 88:
                            raise ValueError(f'Malformed row: {member.filename}:{line}')
                        values = [float(row[i]) for i in feature_indices]
                        digest = feature_digest(values)
                        group = groups.get(digest)
                        if group is not None:
                            label, timestamp = row[label_i].strip(), row[time_i].strip()
                            if label not in FAMILIES or not timestamp.startswith('2018-11-03 '):
                                raise ValueError('Unexpected target label or timestamp')
                            if group['features'] is None:
                                group['features'] = values
                            update_context(group, label, member.filename, timestamp, row[proto_i].strip(), row[port_i].strip(), line)
                        if rows % 100000 == 0:
                            write_json(OUT / 'progress.json', {'status': 'running', 'rows': rows, 'target_rows': sum(sum(g['labels'].values()) for g in groups.values()), 'elapsed_seconds': round(time.time()-start, 1)})
        if rows != audit['roles']['assessment']['rows']:
            raise ValueError('Assessment row count mismatch')
        result_groups = []
        for digest, group in groups.items():
            counts = selected[digest]['audit_counts']
            benign = group['labels'].get('BENIGN', 0)
            attacks = sum(group['labels'].values()) - benign
            if (benign, attacks) != (counts['assessment_benign'], counts['assessment_attack']) or group['features'] is None:
                raise ValueError(f'Target group counts do not match audit: {digest}')
            predictions = {}
            for name, (model, old, calibrated) in models.items():
                score = float(attack_scores(model, np.asarray([group['features']], dtype=np.float64))[0])
                predictions[name] = {'score': score, 'experiment006_threshold': old, 'experiment006_alert': score >= old,
                                     'recalibrated_threshold': calibrated, 'recalibrated_alert': score >= calibrated}
            result_groups.append({'digest': digest, **selected[digest], 'features': dict(zip([v[0] for v in FEATURES.values()], group['features'])),
                                  'raw_labels': dict(group['labels']), 'members': dict(group['members']), 'protocols': dict(group['protocols']),
                                  'top_destination_ports': group['destination_ports'].most_common(10), 'by_label': group['by_label'], 'models': predictions})
        for path, key in ((archive, 'source_sha256'), (AUDIT / 'report.json', 'audit_report_sha256'), (AUDIT / 'groups.sqlite', 'audit_db_sha256'),
                          (ADAPTER, 'adapter_sha256'), (CAL / 'thresholds.json', 'thresholds_sha256'), (Path(__file__), 'runner_sha256')):
            if sha256(path) != fingerprint[key]:
                raise ValueError(f'Input changed during investigation: {path.name}')
        for name, digest in protocol['model_hashes'].items():
            if sha256(MODELS / name / 'bundle.joblib') != digest:
                raise ValueError('Model changed during investigation')
        result = {'status': 'complete', 'rows': rows, 'group_count': len(result_groups), 'groups': result_groups,
                  'protocol_sha256': sha256(OUT / 'protocol.json'), 'elapsed_seconds': round(time.time()-start, 1)}
        write_json(OUT / 'report.json', result)
        write_json(OUT / 'progress.json', {'status': 'complete', 'rows': rows, 'groups': len(result_groups), 'elapsed_seconds': result['elapsed_seconds']})
    except BaseException as exc:
        write_json(OUT / 'progress.json', {'status': 'failed', 'rows': rows, 'error': repr(exc)})
        raise


if __name__ == '__main__':
    main()
