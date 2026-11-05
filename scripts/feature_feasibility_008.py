"""Development-only analysis of protocol and TCP-flag feature collisions."""
import csv
import io
import json
import math
import sys
import time
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from attack_traffic.experiment007_input import sha256
from attack_traffic.original import ORIGINAL_FEATURES
from attack_traffic.prepare import FEATURES
from scripts.assess_experiment007 import write_json

OUT = ROOT / 'artifacts/experiment-008-feature-feasibility'
FLAGS = ('FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'ECE Flag Count')
NAMES = [item[0] for item in FEATURES.values()]
DAYS = {'2017-07-03', '2017-07-04', '2017-07-05'}
SOURCES = {'original': ('data/original/GeneratedLabelledFlows.zip', 'data/original/subset-1pct-capture-date'),
           'corrected': ('data/cns2022/CICIDS2017_improved.zip', 'data/cns2022/subset-1pct-capture-date')}


def collision_summary(records, mode):
    groups = defaultdict(Counter)
    for row in records:
        extras = {'base': (), 'protocol': row['extra'][:1], 'flags': row['extra'][1:], 'protocol_and_flags': row['extra']}[mode]
        groups[row['features'] + extras][row['label']] += 1
    conflicts = [v for v in groups.values() if v[0] and v[1]]
    return {'groups': len(groups), 'conflicting_groups': len(conflicts),
            'rows_in_conflicting_groups': sum(sum(c.values()) for c in conflicts),
            'minority_label_rows_lower_bound': sum(min(c[0], c[1]) for c in conflicts)}


def main():
    inputs = {}
    for variant, (archive, folder) in SOURCES.items():
        paths = [ROOT / archive, ROOT / folder / 'flows.csv', ROOT / folder / 'config.json', ROOT / folder / 'preparation.json']
        hashes = {p.relative_to(ROOT).as_posix(): sha256(p) for p in paths}
        acquisition = json.loads((ROOT / ('data/original/acquisition.json' if variant == 'original' else 'data/cns2022/acquisition.json')).read_text(encoding='utf-8'))
        if hashes[archive] != acquisition['sha256']:
            raise ValueError(f'{variant} archive does not match acquisition fingerprint')
        inputs[variant] = hashes
    OUT.mkdir(parents=True, exist_ok=False)
    plan = {'scope': 'existing 1% sampled CICIDS2017 Monday-Wednesday rows only; no 2019 assessment',
            'selection': 'capture_date in 2017-07-03, 2017-07-04, 2017-07-05; retain valid 27-feature rows',
            'features': {'protocol': ['Protocol'], 'flags': list(FLAGS)},
            'modes': ['base', 'protocol', 'flags', 'protocol_and_flags'],
            'collision_definition': 'exact numeric feature vectors with both mapped binary labels; count all sampled rows',
            'limitation': 'descriptive development collision analysis, not a model accuracy evaluation',
            'script_sha256': sha256(Path(__file__)), 'input_hashes': inputs}
    write_json(OUT / 'protocol.json', plan)
    started = time.time()
    all_results = {}
    for variant, (archive_name, folder_name) in SOURCES.items():
        folder, archive = ROOT / folder_name, ROOT / archive_name
        config = json.loads((folder / 'config.json').read_text(encoding='utf-8'))
        dataset = config['datasets'][0]
        mapping = dataset.get('label_map', config.get('label_map', {}))
        wanted = defaultdict(dict)
        counts = Counter()
        with (folder / 'flows.csv').open(encoding='utf-8-sig', newline='') as stream:
            for row in csv.DictReader(stream):
                if row['capture_date'] not in DAYS:
                    continue
                counts['sampled_rows'] += 1
                try:
                    values = tuple(float(row[n]) for n in NAMES)
                except ValueError:
                    counts['invalid_base'] += 1; continue
                if not all(math.isfinite(v) for v in values) or values[0] < 0:
                    counts['invalid_base'] += 1; continue
                label = mapping.get(row['source_label'])
                if not label or label.get('binary') not in (0, 1):
                    raise ValueError('Missing development label mapping')
                record = int(row['origin_record'])
                if record in wanted[row['origin_member']]:
                    raise ValueError('Duplicate source reference')
                wanted[row['origin_member']][record] = {'features': values, 'label': int(label['binary']), 'source_label': row['source_label']}
        records = []
        invalid_extra = Counter()
        feature_distributions = {name: Counter() for name in ('Protocol', *FLAGS)}
        source_features = ORIGINAL_FEATURES if variant == 'original' else FEATURES
        with zipfile.ZipFile(archive) as bundle:
            for member, targets in sorted(wanted.items()):
                with bundle.open(member) as raw, io.TextIOWrapper(raw, encoding='utf-8-sig', newline='') as text:
                    reader = csv.reader(text)
                    headers = [h.strip().lstrip('\ufeff') for h in next(reader)]
                    required = list(source_features) + ['Label', 'Protocol', *FLAGS]
                    if any(headers.count(name) != 1 for name in required):
                        raise ValueError(f'Ambiguous or missing required field in {member}')
                    indices = [headers.index(name) for name in source_features]
                    label_i = headers.index('Label')
                    extra_i = [headers.index(name) for name in ('Protocol', *FLAGS)]
                    for number, row in enumerate(reader, 2):
                        if number not in targets:
                            continue
                        target = targets.pop(number)
                        if len(row) != len(headers) or row[label_i].strip() != target['source_label']:
                            raise ValueError(f'Source label or width mismatch: {member}:{number}')
                        if tuple(float(row[i]) for i in indices) != target['features']:
                            raise ValueError(f'Source features mismatch: {member}:{number}')
                        try:
                            extra = tuple(float(row[i]) for i in extra_i)
                        except ValueError:
                            invalid_extra['nonnumeric'] += 1; continue
                        if not all(math.isfinite(x) and x >= 0 and x.is_integer() for x in extra) or extra[0] > 255:
                            invalid_extra['invalid_range'] += 1; continue
                        target['extra'] = tuple(int(x) for x in extra)
                        for name, value in zip(('Protocol', *FLAGS), target['extra']):
                            feature_distributions[name][str(value)] += 1
                        records.append(target)
                        if not targets:
                            break
                if targets:
                    raise ValueError(f'Source references not found in {member}: {len(targets)}')
                write_json(OUT / 'progress.json', {'status': 'running', 'variant': variant, 'member': member, 'matched_valid_rows': len(records), 'elapsed_seconds': round(time.time()-started, 1)})
        modes = {mode: collision_summary(records, mode) for mode in ('base', 'protocol', 'flags', 'protocol_and_flags')}
        all_results[variant] = {'sampled_rows': counts['sampled_rows'], 'invalid_base': counts['invalid_base'], 'invalid_extra': dict(invalid_extra),
                                'analyzed_rows': len(records), 'labels': dict(Counter('attack' if r['label'] else 'benign' for r in records)),
                                'feature_values': {name: dict(sorted(c.items())) for name, c in feature_distributions.items()}, 'collision_modes': modes}
    for hashes in inputs.values():
        for path, expected in hashes.items():
            if sha256(ROOT / path) != expected:
                raise ValueError(f'Input changed during scan: {path}')
    if sha256(Path(__file__)) != plan['script_sha256']:
        raise ValueError('Script changed during scan')
    result = {'status': 'complete', 'protocol_sha256': sha256(OUT / 'protocol.json'), 'variants': all_results, 'elapsed_seconds': round(time.time()-started, 1)}
    write_json(OUT / 'report.json', result)
    write_json(OUT / 'progress.json', {'status': 'complete', 'elapsed_seconds': result['elapsed_seconds']})


if __name__ == '__main__':
    main()
