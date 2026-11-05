"""Check a proposed external evaluation input; never score or select a model.

Independence and units are declarations, not facts this checker can establish.
Identical feature vectors are conservatively rejected, not proof of shared flows.
The caller must freeze the model and threshold before inspecting evaluation data.
"""
import csv
import json
import math
import re
from pathlib import Path

from .prepare import FEATURES
from .support_extract import feature_digest
from .tune import _sha


def validate_external_contract(csv_path, manifest_path, frozen_splits, expected_splits_sha256):
    """Validate a canonical labelled CSV and independently sourced capture claim.

    Manifest keys: schema_version=1, csv_sha256, source_name, source_url,
    capture_description, independence_attestation (a nonempty explanation),
    feature_units (exact canonical mapping), and label_map (raw label to 0/1).
    Input header must be record_id,source_label followed by the canonical features.
    All recorded frozen feature groups are conservatively excluded. No training,
    threshold selection, score calculation or report file is performed.
    """
    csv_path, manifest_path, frozen_splits = map(Path, (csv_path, manifest_path, frozen_splits))
    try:
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError('Cannot read external manifest') from exc
    if not isinstance(manifest, dict) or manifest.get('schema_version') != 1:
        raise ValueError('Unsupported manifest schema')
    for key in ('source_name', 'source_url', 'capture_description', 'independence_attestation'):
        if not isinstance(manifest.get(key), str) or not manifest[key].strip():
            raise ValueError(f'Missing {key}')
    if not re.fullmatch(r'[0-9a-f]{64}', str(expected_splits_sha256)) or _sha(frozen_splits) != expected_splits_sha256:
        raise ValueError('Frozen split hash mismatch')
    if not re.fullmatch(r'[0-9a-f]{64}', str(manifest.get('csv_sha256'))) or _sha(csv_path) != manifest['csv_sha256']:
        raise ValueError('External CSV hash mismatch')
    names = [value[0] for value in FEATURES.values()]
    units = {value[0]: value[1] for value in FEATURES.values()}
    if manifest.get('feature_units') != units:
        raise ValueError('Feature units differ from canonical schema')
    labels = manifest.get('label_map')
    if not isinstance(labels, dict) or not labels or any(not isinstance(k, str) or not k.strip() or type(v) is not int or v not in (0, 1) for k, v in labels.items()):
        raise ValueError('Invalid label map')
    blocked = set()
    with frozen_splits.open(newline='', encoding='utf-8-sig') as stream:
        reader = csv.DictReader(stream)
        if 'duplicate_group_id' not in (reader.fieldnames or []):
            raise ValueError('Missing frozen group identities')
        for row in reader:
            digest = row['duplicate_group_id']
            if digest and not re.fullmatch(r'[0-9a-f]{64}', digest):
                raise ValueError('Malformed frozen group identity')
            if digest:
                blocked.add(digest)
    ids = set()
    with csv_path.open(newline='', encoding='utf-8-sig') as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != ['record_id', 'source_label', *names]:
            raise ValueError('External CSV schema mismatch')
        for row in reader:
            if None in row or any(value is None for value in row.values()):
                raise ValueError('Malformed external CSV row')
            record_id = row['record_id']
            if not record_id or record_id != record_id.strip() or record_id in ids:
                raise ValueError('Invalid or duplicated record ID')
            ids.add(record_id)
            if row['source_label'] not in labels:
                raise ValueError('Unknown external label')
            try:
                numbers = [float(row[name]) for name in names]
            except ValueError as exc:
                raise ValueError('Invalid external feature') from exc
            if not all(math.isfinite(number) for number in numbers) or numbers[0] < 0:
                raise ValueError('Invalid external feature')
            if feature_digest(numbers) in blocked:
                raise ValueError('External feature group matches a frozen group')
    if not ids:
        raise ValueError('External CSV is empty')
    if _sha(csv_path) != manifest['csv_sha256'] or _sha(frozen_splits) != expected_splits_sha256:
        raise ValueError('Input changed during validation')
    return {'status': 'contract_checks_passed', 'rows': len(ids),
            'csv_sha256': manifest['csv_sha256'], 'frozen_splits_sha256': expected_splits_sha256,
            'limitations': 'Capture independence, units, label correctness and model freeze require independent verification; feature-vector equality is not flow identity.'}
