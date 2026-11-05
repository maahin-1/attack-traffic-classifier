"""Read-only quality inventory of the designated IDS2018 development day.

Column aliases are hypotheses only; this check does not certify semantics.
"""
import csv
import json
import math
from collections import Counter
from pathlib import Path

from .prepare import FEATURES
from .tune import _sha

FILENAME = 'Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv'
ALIASES = [
    'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts',
    'TotLen Bwd Pkts', 'Fwd Pkt Len Max', 'Fwd Pkt Len Min',
    'Fwd Pkt Len Mean', 'Fwd Pkt Len Std', 'Bwd Pkt Len Max',
    'Bwd Pkt Len Min', 'Bwd Pkt Len Mean', 'Bwd Pkt Len Std',
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Tot', 'Bwd IAT Tot', 'Active Mean', 'Active Std',
    'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min',
]


def inspect_development(csv_path, acquisition_path, output_path):
    csv_path, acquisition_path, output_path = map(Path, (csv_path, acquisition_path, output_path))
    if csv_path.name != FILENAME:
        raise ValueError('Only the designated development CSV is supported')
    if output_path.exists():
        raise ValueError('Output already exists')
    acquisition = json.loads(acquisition_path.read_text(encoding='utf-8'))
    digest = _sha(csv_path)
    if (acquisition.get('file') != FILENAME or acquisition.get('role') != 'development schema inspection only'
            or acquisition.get('sha256') != digest or acquisition.get('bytes') != csv_path.stat().st_size):
        raise ValueError('Acquisition record mismatch')
    labels, invalid, dispositions = Counter(), Counter(), Counter()
    with csv_path.open(newline='', encoding='utf-8-sig') as stream:
        reader = csv.reader(stream)
        headers = next(reader, None)
        if not headers or len(headers) != len(set(headers)) or not set(ALIASES + ['Label']).issubset(headers):
            raise ValueError('Missing or ambiguous headers')
        positions = [headers.index(name) for name in ALIASES]
        label_index = headers.index('Label')
        for row in reader:
            dispositions['csv_records'] += 1
            if row == headers:
                dispositions['embedded_header'] += 1
                continue
            if len(row) != len(headers):
                dispositions['malformed_width'] += 1
                continue
            dispositions['data_rows'] += 1
            labels[row[label_index].strip()] += 1
            row_bad = False
            for alias, position in zip(ALIASES, positions):
                try:
                    value = float(row[position])
                    if not math.isfinite(value) or (alias == 'Flow Duration' and value < 0):
                        raise ValueError
                except ValueError:
                    invalid[alias] += 1
                    row_bad = True
            if row_bad:
                dispositions['rows_invalid_required_features'] += 1
    if _sha(csv_path) != digest:
        raise ValueError('Input changed during inspection')
    result = {
        'schema_version': 1, 'file': FILENAME, 'sha256': digest,
        'role': 'development schema inspection only',
        'records': dict(dispositions), 'labels': dict(sorted(labels.items())),
        'invalid_feature_values': {alias: invalid[alias] for alias in ALIASES},
        'aliases': [dict(source=alias, canonical=canonical, expected_unit=unit)
                    for alias, (canonical, unit) in zip(ALIASES, FEATURES.values())],
        'limitations': 'Header correspondence is provisional; units, extraction semantics and labels require independent verification. No model scoring.',
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    return result
