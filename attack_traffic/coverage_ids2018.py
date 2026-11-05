"""Read-only CSV coverage evidence; clock strings do not establish UTC coverage."""
import csv
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from .tune import _sha


def inspect_coverage(csv_path, acquisition_path):
    path = Path(csv_path)
    acquisition = json.loads(Path(acquisition_path).read_text(encoding='utf-8'))
    digest = _sha(path)
    if acquisition['file'] != path.name or acquisition['sha256'] != digest or acquisition['bytes'] != path.stat().st_size:
        raise ValueError('Acquisition hash or size mismatch')
    counts, hours, dates = Counter(), Counter(), Counter()
    labels = defaultdict(lambda: {'rows': 0, 'invalid_timestamp': 0, 'minimum_clock': None, 'maximum_clock': None})
    boundaries = []
    previous = None
    with path.open(newline='', encoding='utf-8-sig') as stream:
        reader = csv.reader(stream)
        header = next(reader)
        if len(header) != len(set(header)) or not {'Timestamp', 'Label'}.issubset(header):
            raise ValueError('Ambiguous coverage schema')
        ti, li = header.index('Timestamp'), header.index('Label')
        for ordinal, row in enumerate(reader, 2):
            counts['csv_records'] += 1
            if row == header:
                counts['repeated_header'] += 1
                continue
            if len(row) != len(header):
                counts['malformed_width'] += 1
                continue
            counts['data_rows'] += 1
            label = row[li].strip()
            entry = labels[label]
            entry['rows'] += 1
            stamp = row[ti].strip()
            try:
                parsed = datetime.strptime(stamp, '%d/%m/%Y %H:%M:%S')
            except ValueError:
                counts['invalid_timestamp'] += 1
                entry['invalid_timestamp'] += 1
                continue
            iso = parsed.isoformat()
            dates[parsed.date().isoformat()] += 1
            hours[f'{parsed.date().isoformat()} {parsed.hour:02d}'] += 1
            entry['minimum_clock'] = min(entry['minimum_clock'] or iso, iso)
            entry['maximum_clock'] = max(entry['maximum_clock'] or iso, iso)
            if previous and iso < previous:
                counts['clock_decreases_in_source_order'] += 1
            previous = iso
            boundary = {'ordinal': ordinal, 'clock': iso, 'source_label': label}
            if not boundaries:
                boundaries.append(boundary)
            last = boundary
    if counts['data_rows'] and 'last' in locals():
        boundaries.append(last)
    if _sha(path) != digest:
        raise ValueError('Input changed during inspection')
    return {'file': path.name, 'bytes': path.stat().st_size, 'sha256': digest,
            'counts': dict(counts), 'dates': dict(sorted(dates.items())),
            'hourly_wall_clock_rows': dict(sorted(hours.items())),
            'source_boundaries': boundaries, 'per_label': dict(sorted(labels.items())),
            'scope': 'Observed source clock strings only; no timezone/AM-PM recovery or completeness claim.'}


def audit_coverage(data_root, output_path, commitment_path='artifacts/ids2018-prescore-commitment-v2.json'):
    root, output = Path(data_root), Path(output_path)
    if output.exists():
        raise ValueError('Output exists')
    files = [(root/'Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv', root/'acquisition-development.json')]
    expected = {'Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv', 'Friday-16-02-2018_TrafficForML_CICFlowMeter.csv'}
    actual = list((root/'reserved').glob('*.csv'))
    if {p.name for p in actual} != expected or len(actual) != 2:
        raise ValueError('Expected exact 15 and 16 February reserved CSV identities')
    commitment = json.loads(Path(commitment_path).read_text(encoding='utf-8'))
    if set(commitment.get('data_sha256', {})) != expected or set(commitment.get('acquisition_sha256', {})) != expected:
        raise ValueError('Incomplete reserved-file commitment')
    for p in sorted(actual):
        acquisition = Path(str(p)+'.acquisition.json')
        if _sha(p) != commitment['data_sha256'][p.name] or _sha(acquisition) != commitment['acquisition_sha256'][p.name]:
            raise ValueError('Reserved input differs from pre-scoring commitment')
        files.append((p, acquisition))
    result = {'schema_version': 1, 'files': [inspect_coverage(*item) for item in files],
              'limitations': 'Matching object lengths and recorded hashes establish complete local copies, not complete underlying capture or an authenticated publisher checksum.'}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    return result
