"""Streaming quality/coverage inventory of the regenerated development member.

No model scores or endpoint values are exported. The proposed binary labels are
diagnostic accounting only; source labels and attempted categories are retained.
"""
import csv
import hashlib
import json
import math
import zlib
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from .prepare import FEATURES

MEMBER = 'Wednesday-14-02-2018.csv'
EXPECTED_LABELS = {'Benign', 'BENIGN', 'FTP-BruteForce', 'FTP-BruteForce - Attempted',
                   'SSH-BruteForce', 'SSH-BruteForce - Attempted'}


def _fingerprint(path):
    sha, crc, size = hashlib.sha256(), 0, 0
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            sha.update(block)
            crc = zlib.crc32(block, crc)
            size += len(block)
    return {'sha256': sha.hexdigest(), 'bytes': size, 'crc32': f'{crc & 0xffffffff:08x}'}


def inspect_corrected_development(csv_path, acquisition_path, output_path):
    path, acquisition_path, output = map(Path, (csv_path, acquisition_path, output_path))
    if path.name != MEMBER or output.exists():
        raise ValueError('Require designated development member and fresh output')
    acquisition_bytes = acquisition_path.read_bytes()
    acquisition = json.loads(acquisition_bytes)
    fingerprint = _fingerprint(path)
    # Manifest requirements are aligned with acquire_corrected2018.py.
    if (acquisition.get('file') != MEMBER or acquisition.get('sha256') != fingerprint['sha256']
            or acquisition.get('bytes') != fingerprint['bytes']
            or acquisition.get('role') != 'corrected 2018 development member only; no model scoring'
            or acquisition.get('member_crc32_verified') != fingerprint['crc32']):
        raise ValueError('Acquisition identity, hash, size or CRC verification mismatch')
    counts, labels, categories, proposed = Counter(), Counter(), Counter(), Counter()
    dates, hours, label_categories = Counter(), Counter(), Counter()
    issue_counts = {name: Counter() for name in FEATURES}
    label_times = defaultdict(lambda: {'rows': 0, 'invalid_timestamp': 0, 'minimum': None, 'maximum': None})
    previous = None
    first = last = None
    with path.open(newline='', encoding='utf-8-sig') as stream:
        reader = csv.reader(stream)
        header = next(reader, [])
        required = set(FEATURES) | {'Label', 'Attempted Category', 'Timestamp'}
        if len(header) != 91 or len(set(header)) != 91 or not required.issubset(header):
            raise ValueError('Expected 91 unique corrected columns and required schema')
        indexes = {name: header.index(name) for name in required}
        for ordinal, row in enumerate(reader, 2):
            counts['csv_records'] += 1
            if row == header:
                counts['repeated_header'] += 1
                continue
            if len(row) != len(header):
                counts['malformed_width'] += 1
                continue
            counts['data_rows'] += 1
            label, category = row[indexes['Label']].strip(), row[indexes['Attempted Category']].strip()
            labels[label] += 1
            categories[category] += 1
            label_categories[(label, category)] += 1
            attempted = 'attempted' in label.casefold()
            benign = label.casefold() == 'benign'
            try:
                category_number = int(category)
                if category_number not in range(-1, 7):
                    raise ValueError
            except ValueError:
                category_number = None
                counts['invalid_attempted_category'] += 1
            if category_number is not None:
                if attempted != (category_number != -1):
                    counts['attempted_label_category_disagreement'] += 1
                if benign and category_number != -1:
                    counts['benign_label_with_attempted_category'] += 1
                if label in EXPECTED_LABELS:
                    proposed['benign' if benign or category_number != -1 else 'attack'] += 1
            if category_number is None or label not in EXPECTED_LABELS:
                counts['unresolved_proposed_binary'] += 1
            if label not in EXPECTED_LABELS:
                counts['unknown_or_empty_label'] += 1
            if not label:
                counts['empty_label'] += 1
            row_invalid = False
            for name in FEATURES:
                text = row[indexes[name]].strip()
                if not text:
                    issue_counts[name]['missing'] += 1
                    row_invalid = True
                    continue
                try:
                    value = float(text)
                except ValueError:
                    issue_counts[name]['nonnumeric'] += 1
                    row_invalid = True
                    continue
                if not math.isfinite(value):
                    issue_counts[name]['nonfinite'] += 1
                    row_invalid = True
                elif value < 0:
                    issue_counts[name]['negative'] += 1
                    if name == 'Flow Duration':
                        row_invalid = True
            counts['rows_invalid_required_features'] += int(row_invalid)
            timing = label_times[label]
            timing['rows'] += 1
            try:
                value = datetime.strptime(row[indexes['Timestamp']].strip(), '%Y-%m-%d %H:%M:%S.%f')
            except ValueError:
                counts['invalid_timestamp'] += 1
                timing['invalid_timestamp'] += 1
                continue
            iso = value.isoformat(timespec='microseconds')
            dates[value.date().isoformat()] += 1
            hours[value.strftime('%Y-%m-%d %H')] += 1
            counts['wrong_capture_date'] += int(value.date().isoformat() != '2018-02-14')
            timing['minimum'] = min(timing['minimum'] or iso, iso)
            timing['maximum'] = max(timing['maximum'] or iso, iso)
            counts['timestamp_decreases_in_source_order'] += int(previous is not None and value < previous)
            previous = value
            boundary = {'csv_record_ordinal': ordinal, 'timestamp': iso, 'source_label': label}
            if first is None:
                first = boundary
            last = boundary
    if _fingerprint(path) != fingerprint or acquisition_path.read_bytes() != acquisition_bytes:
        raise ValueError('Input changed during inventory')
    if counts['csv_records'] != counts['data_rows'] + counts['repeated_header'] + counts['malformed_width']:
        raise ValueError('Row accounting mismatch')
    if sum(labels.values()) != counts['data_rows'] or sum(proposed.values()) + counts['unresolved_proposed_binary'] != counts['data_rows']:
        raise ValueError('Label accounting mismatch')
    result = {
        'schema_version': 1, 'member': MEMBER, 'fingerprint': fingerprint,
        'acquisition_sha256': hashlib.sha256(acquisition_bytes).hexdigest(),
        'counts': dict(counts), 'labels': dict(sorted(labels.items())), 'attempted_categories': dict(sorted(categories.items())),
        'label_category_support': [{'label': label, 'category': category, 'rows': n} for (label, category), n in sorted(label_categories.items())],
        'proposed_binary_support': dict(proposed),
        'feature_issues': {name: dict(value) for name, value in issue_counts.items()},
        'dates': dict(sorted(dates.items())), 'hourly_timestamp_rows': dict(sorted(hours.items())),
        'per_label_timing': dict(sorted(label_times.items())), 'first_parseable_source_row': first, 'last_parseable_source_row': last,
        'schema_columns': header,
        'scope': 'Development-only inventory; no model scoring, exclusions or transformed data published.',
        'policy': 'Only documented development Benign/FTP-BruteForce/SSH-BruteForce and their Attempted suffix variants with categories -1..6 receive proposed binary accounting; Benign or category != -1 maps benign. Unknown/empty labels or invalid/unsupported categories are unresolved. Raw source labels are not verified ground truth.',
        'limitations': 'CRC verifies member integrity against ZIP metadata, not authenticity. CSV row/time coverage does not prove complete underlying PCAP capture. UTC semantics follow release documentation, not independent clock verification. Exact historical extractor version remains unresolved.'}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write('\n')
    return result


def review_proposed_support(inventory_path, acquisition_path, output_path):
    """Explicit post-schema alias review; derive support without rescanning CSV."""
    inventory_path, acquisition_path, output = map(Path, (inventory_path, acquisition_path, output_path))
    if output.exists():
        raise ValueError('Output already exists')
    raw = inventory_path.read_bytes()
    acquisition = acquisition_path.read_bytes()
    inventory = json.loads(raw)
    if inventory['member'] != MEMBER or inventory['acquisition_sha256'] != hashlib.sha256(acquisition).hexdigest():
        raise ValueError('Inventory/acquisition mismatch')
    manifest = json.loads(acquisition)
    if (manifest['sha256'] != inventory['fingerprint']['sha256']
            or manifest['member_crc32_verified'] != inventory['fingerprint']['crc32']
            or manifest['bytes'] != inventory['fingerprint']['bytes']):
        raise ValueError('Inventory/acquisition fingerprint mismatch')
    observed, support, category_counts = Counter(), Counter(), Counter()
    for entry in inventory['label_category_support']:
        label, category, count = entry['label'], int(entry['category']), entry['rows']
        if label not in EXPECTED_LABELS or category not in range(-1, 7) or type(count) is not int or count < 0:
            raise ValueError('Unreviewed label/category/support')
        if ('attempted' in label.casefold()) != (category != -1):
            raise ValueError('Label/category mismatch')
        observed[label] += count
        category_counts[str(category)] += count
        support['benign' if label.casefold() == 'benign' or category != -1 else 'attack'] += count
    if dict(observed) != inventory['labels'] or dict(category_counts) != inventory['attempted_categories'] or sum(observed.values()) != inventory['counts']['data_rows']:
        raise ValueError('Support reconciliation failed')
    if inventory['counts'].get('invalid_timestamp', 0) or any(date not in ('2018-02-14', '2018-02-15') for date in inventory['dates']):
        raise ValueError('Unexpected timestamp population')
    for label, entry in inventory['per_label_timing'].items():
        if label.casefold() != 'benign' and (not entry['minimum'].startswith('2018-02-14') or not entry['maximum'].startswith('2018-02-14')):
            raise ValueError('Non-benign cross-date support unresolved')
    cross_date = inventory['dates'].get('2018-02-15', 0)
    if inventory['counts'].get('wrong_capture_date', 0) != cross_date:
        raise ValueError('Cross-date accounting mismatch')
    result = {'schema_version': 1, 'inventory_sha256': hashlib.sha256(raw).hexdigest(),
        'acquisition_sha256': hashlib.sha256(acquisition).hexdigest(),
        'decision': 'After raw-label inspection, explicitly accept BENIGN as the source spelling of benign. First immutable inventory remains unchanged; no source rows were dropped or relabeled in a dataset.',
        'proposed_binary_support': dict(support), 'cross_date_rows': cross_date,
        'cross_date_label': 'BENIGN',
        'cross_date_evidence': 'Only benign label timing extends beyond 14 February; all other label minima/maxima are within that date and there are no timestamp parse failures.',
        'scope': 'Derived reviewed accounting only; no model scoring or transformed training data.'}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write('\n')
    return result
