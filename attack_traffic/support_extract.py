"""Extract an additional nested training sample for Experiment 005.

Only early-day archive members are parsed. The frozen split ledger contributes
feature-group IDs and source references, never held-out labels or scores.
"""
import csv
import hashlib
import io
import json
import math
import shutil
import tempfile
import zipfile
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

from .original import ORIGINAL_FEATURES, ORIGINAL_LABEL_MAP, ORIGINAL_MEMBERS, _headers, original_clock_interval
from .prepare import FEATURES, selected_record
from .tune import SOURCE_FILES, _json, _sha


def feature_digest(values):
    normalized = [0.0 if value == 0 else value for value in values]
    return hashlib.sha256(json.dumps(normalized, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def extract_training_support(source, original_archive, original_acquisition,
                             corrected_archive, corrected_acquisition, output):
    source, output = Path(source).resolve(), Path(output).resolve()
    if output.exists():
        raise ValueError('Output already exists')
    reference = _json(source.parent / 'experiment-004-features/provenance.json')
    expected_sources = reference.get('source_files', {})
    if set(expected_sources) != set(SOURCE_FILES) or any(_sha(source / name) != expected_sources[name] for name in SOURCE_FILES):
        raise ValueError('Frozen source does not match Experiment 004 provenance')
    config = _json(source / 'config.json')
    if config.get('temporal_basis') != 'capture_date' or config['boundaries']['validation_start'] != '2017-07-05':
        raise ValueError('Expected the frozen capture-date experiment')
    features = list(FEATURES.values())
    names = [item[0] for item in features]
    if config['feature_allowlist'] != names:
        raise ValueError('Frozen feature order mismatch')
    variants = {d['variant']: d for d in config['datasets']}
    if set(variants) != {'original', 'corrected'}:
        raise ValueError('Expected both dataset variants')
    blocked = {v: set() for v in variants}
    existing = {v: set() for v in variants}
    with (source / 'audit/splits.csv').open(encoding='utf-8', newline='') as stream:
        reader = csv.DictReader(stream)
        required = {'variant', 'partition', 'duplicate_group_id', 'origin_member', 'origin_record'}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError('Incomplete frozen split ledger')
        for row in reader:
            variant = row['variant']
            if variant not in variants:
                raise ValueError('Unknown ledger variant')
            digest = row['duplicate_group_id']
            if digest:
                if len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
                    raise ValueError('Invalid group identity')
                blocked[variant].add(digest)
            if row['partition'] == 'train':
                existing[variant].add((row['origin_member'], row['origin_record']))
    archives = {'original': (Path(original_archive), Path(original_acquisition)),
                'corrected': (Path(corrected_archive), Path(corrected_acquisition))}
    hashes = {}
    for variant, (archive, acquisition) in archives.items():
        digest = _sha(archive)
        if _json(acquisition).get('sha256') != digest:
            raise ValueError(f'{variant} archive hash mismatch')
        preparation = variants[variant].get('preparation', {})
        if preparation.get('archive_sha256') != digest or preparation.get('denominator') != 100:
            raise ValueError(f'{variant} baseline archive or sampling mismatch')
        hashes[variant] = digest
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='.support-', dir=output.parent))
    counts = {v: Counter() for v in variants}
    try:
        with (stage / 'supplement.csv').open('w', newline='', encoding='utf-8') as out, (stage / 'exclusions.csv').open('w', newline='', encoding='utf-8') as ledger:
            writer = csv.DictWriter(out, fieldnames=['variant', 'origin_member', 'origin_record', 'source_label', 'family', 'binary_label', 'duplicate_group_id', *names])
            writer.writeheader()
            exclusions = csv.DictWriter(ledger, fieldnames=['variant', 'origin_member', 'origin_record', 'reason'])
            exclusions.writeheader()
            for variant in ('original', 'corrected'):
                with zipfile.ZipFile(archives[variant][0]) as bundle:
                    members = sorted(m for m in bundle.namelist() if Path(m).name.lower().startswith(('monday', 'tuesday')))
                    expected = sorted(m for m in ORIGINAL_MEMBERS if Path(m).name.lower().startswith(('monday', 'tuesday'))) if variant == 'original' else ['monday.csv', 'tuesday.csv']
                    if members != expected or len(set(bundle.namelist())) != len(bundle.namelist()):
                        raise ValueError('Unexpected early-day archive members')
                    for member in members:
                        encoding = 'cp1252' if variant == 'original' else 'utf-8-sig'
                        with bundle.open(member) as raw, io.TextIOWrapper(raw, encoding=encoding, newline='') as text:
                            reader = csv.reader(text)
                            headers = next(reader)
                            if variant == 'original':
                                headers, indexes, _ = _headers(headers, member)
                                source_fields = list(ORIGINAL_FEATURES)
                            else:
                                if len(set(headers)) != len(headers) or not set(FEATURES).union({'Timestamp', 'Label'}).issubset(headers):
                                    raise ValueError('Unexpected corrected schema')
                                indexes = {name: i for i, name in enumerate(headers)}
                                source_fields = list(FEATURES)
                            for ordinal, row in enumerate(reader, 2):
                                if not selected_record(hashes[variant], member, ordinal, 10) or selected_record(hashes[variant], member, ordinal, 100):
                                    continue
                                counts[variant]['nested_selected'] += 1
                                if len(row) != len(headers):
                                    raise ValueError('Malformed sampled row')
                                if not any(cell.strip() for cell in row):
                                    counts[variant]['padding'] += 1
                                    exclusions.writerow(dict(variant=variant, origin_member=member, origin_record=ordinal, reason='padding'))
                                    continue
                                if (member, str(ordinal)) in existing[variant]:
                                    raise ValueError('Nested sample overlaps frozen sample')
                                label = row[indexes['Label']].strip()
                                mapping = ORIGINAL_LABEL_MAP if variant == 'original' else variants[variant].get('label_map', config['label_map'])
                                if label not in mapping:
                                    raise ValueError(f'Unknown label {label!r}')
                                try:
                                    values = [float(row[indexes[name]]) for name in source_fields]
                                    if not all(math.isfinite(v) for v in values) or values[0] < 0:
                                        raise ValueError('invalid numeric value')
                                    stamp = row[indexes['Timestamp']].strip()
                                    if variant == 'original':
                                        interval = original_clock_interval(stamp, member, values[0])
                                        end = datetime.fromisoformat(interval['local_end_upper'])
                                    else:
                                        start = datetime.strptime(stamp, '%Y-%m-%d %H:%M:%S.%f')
                                        expected_date = '2017-07-03' if member == 'monday.csv' else '2017-07-04'
                                        if start.date().isoformat() != expected_date:
                                            raise ValueError('capture date mismatch')
                                        end = start + timedelta(microseconds=values[0])
                                    if end >= datetime(2017, 7, 5):
                                        counts[variant]['boundary_quarantine'] += 1
                                        exclusions.writerow(dict(variant=variant, origin_member=member, origin_record=ordinal, reason='boundary_quarantine'))
                                        continue
                                except (ValueError, OverflowError):
                                    counts[variant]['invalid'] += 1
                                    exclusions.writerow(dict(variant=variant, origin_member=member, origin_record=ordinal, reason='invalid_feature_or_time'))
                                    continue
                                digest = feature_digest(values)
                                if digest in blocked[variant]:
                                    counts[variant]['existing_group_quarantine'] += 1
                                    exclusions.writerow(dict(variant=variant, origin_member=member, origin_record=ordinal, reason='existing_group_quarantine'))
                                    continue
                                blocked[variant].add(digest)
                                counts[variant]['retained'] += 1
                                counts[variant]['retained_attack' if mapping[label]['binary'] else 'retained_benign'] += 1
                                writer.writerow(dict(zip(['variant', 'origin_member', 'origin_record', 'source_label', 'family', 'binary_label', 'duplicate_group_id', *names], [variant, member, ordinal, label, mapping[label]['family'], mapping[label]['binary'], digest, *values])))
        for variant, count in counts.items():
            if count['nested_selected'] != sum(count[key] for key in ('padding', 'boundary_quarantine', 'invalid', 'existing_group_quarantine', 'retained')):
                raise ValueError(f'Unreconciled selection accounting for {variant}')
        summary = {'schema_version': 1, 'status': 'ok', 'counts': {v: dict(c) for v, c in counts.items()}, 'archive_sha256': hashes, 'source_files': {f: _sha(source / f) for f in SOURCE_FILES}, 'supplement_sha256': _sha(stage / 'supplement.csv'), 'exclusions_sha256': _sha(stage / 'exclusions.csv'), 'selection': 'subset-v1 modulo 10 = 0 and modulo 100 != 0', 'guard': 'exclude all frozen group hashes, including held-out, without reading held-out labels'}
        (stage / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        stage.rename(output)
    except Exception:
        shutil.rmtree(stage)
        raise
    return output
