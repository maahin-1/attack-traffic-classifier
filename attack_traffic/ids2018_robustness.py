"""Frozen-threshold cross-version evaluation for the two reserved 2018 days.

Trusted-local joblib only. This reports agreement with supplied dataset labels;
feature equivalence, capture independence, and label validity are not certified.
"""
import csv
import json
import math
import shutil
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

from .evaluate import attack_scores
from .freeze_binary import load_binary
from .inspect_ids2018 import ALIASES
from .support_extract import feature_digest
from .tune import _sha

BASE = 'https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/Processed%20Traffic%20Data%20for%20ML%20Algorithms/'
FILES = ('Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv',
         'Friday-16-02-2018_TrafficForML_CICFlowMeter.csv')
LABELS = {'Benign': 0, 'DoS attacks-GoldenEye': 1, 'DoS attacks-Slowloris': 1,
          'DoS attacks-SlowHTTPTest': 1, 'DoS attacks-Hulk': 1}
DEPENDENCIES = ('attack_traffic/inspect_ids2018.py', 'attack_traffic/evaluate.py',
                'attack_traffic/freeze_binary.py', 'attack_traffic/support_extract.py',
                'attack_traffic/tune.py', 'attack_traffic/prepare.py')


def _json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def _read_rows(path):
    with path.open(newline='', encoding='utf-8-sig') as stream:
        reader = csv.reader(stream)
        header = next(reader, None)
        if not header or len(set(header)) != len(header) or not set(ALIASES + ['Label']).issubset(header):
            raise ValueError(f'Ambiguous or incomplete schema: {path.name}')
        indexes = [header.index(name) for name in ALIASES]
        label_index = header.index('Label')
        for ordinal, row in enumerate(reader, 2):
            if row == header:
                yield ordinal, None, None, 'repeated_header'
                continue
            if len(row) != len(header):
                yield ordinal, None, None, 'malformed_width'
                continue
            label = row[label_index].strip()
            if label not in LABELS:
                raise ValueError(f'Unknown label at {path.name}:{ordinal}: {label!r}')
            try:
                values = [float(row[index]) for index in indexes]
                if not all(math.isfinite(value) for value in values) or values[0] < 0:
                    raise ValueError('invalid numeric input')
            except ValueError:
                yield ordinal, None, label, 'invalid_feature'
                continue
            yield ordinal, values, label, None


def _ratio(a, b):
    return a / b if b else None


def _metrics(counts):
    tp, fp, tn, fn = (counts[x] for x in ('tp', 'fp', 'tn', 'fn'))
    return {'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
            'recall': _ratio(tp, tp + fn), 'fpr': _ratio(fp, fp + tn),
            'precision': _ratio(tp, tp + fp), 'zero_score': counts['zero_score']}


def run_robustness(data_dir, model_dir, source_run, commitment_file, output_dir, *, batch_size=8192):
    """Run only after the external protocol and selection are frozen.

    Each file has a sibling ``<filename>.acquisition.json`` recording source,
    SHA-256, size and metadata. Hashes do not authenticate rewritten metadata.
    """
    data, model, source, output = map(lambda x: Path(x).resolve(),
                                      (data_dir, model_dir, source_run, output_dir))
    commitment_file = Path(commitment_file).resolve()
    if output.exists() or any(output.is_relative_to(p) for p in (data, model, source)):
        raise ValueError('Require a fresh, separate output directory')
    if type(batch_size) is not int or batch_size <= 0:
        raise ValueError('Invalid batch size')
    data_hashes = {}
    acquisition_hashes = {}
    for name in FILES:
        acquisition = data / (name + '.acquisition.json')
        entry = _json(acquisition)
        acquisition_hashes[name] = _sha(acquisition)
        file = data / name
        if (entry.get('file') != name or entry.get('source_url') != BASE + name
                or entry.get('role') != 'reserved final external evaluation, no outcomes inspected'
                or not entry.get('etag') or not entry.get('last_modified')
                or entry.get('bytes') != file.stat().st_size or entry.get('sha256') != _sha(file)):
            raise ValueError(f'Invalid acquisition provenance for {name}')
        data_hashes[name] = entry['sha256']
    provenance = _json(model / 'provenance.json')
    if provenance.get('bundle_type') != 'binary_random_forest_v1' or set(provenance.get('variants', {})) != {'original', 'corrected'}:
        raise ValueError('Invalid frozen model provenance')
    for relative, expected in provenance.get('source_files', {}).items():
        if _sha(source / relative) != expected:
            raise ValueError('Frozen source digest mismatch')
    split = source / 'audit/splits.csv'
    expected_split = provenance.get('source_files', {}).get('audit/splits.csv')
    if _sha(split) != expected_split:
        raise ValueError('Frozen split digest mismatch')
    blocked = set()
    with split.open(encoding='utf-8-sig', newline='') as stream:
        reader = csv.DictReader(stream)
        if 'duplicate_group_id' not in (reader.fieldnames or []):
            raise ValueError('Missing frozen group IDs')
        blocked.update(row['duplicate_group_id'] for row in reader if row['duplicate_group_id'])
    model_hashes = {(model / v / name).relative_to(model).as_posix(): _sha(model / v / name)
                    for v in ('original', 'corrected') for name in ('metadata.json', 'bundle.joblib')}
    model_hashes['provenance.json'] = _sha(model / 'provenance.json')
    root = Path(__file__).resolve().parent.parent
    protocol = root / 'docs/IDS2018-ROBUSTNESS-PROTOCOL.md'
    implementation = Path(__file__).resolve()
    dependency_hashes = {relative: _sha(root / relative) for relative in DEPENDENCIES}
    commitment_hash = _sha(commitment_file)
    commitment = _json(commitment_file)
    expected_commitment = {
        'schema_version': 1,
        'data_sha256': data_hashes,
        'acquisition_sha256': acquisition_hashes,
        'model_sha256': model_hashes,
        'source_sha256': provenance['source_files'],
        'protocol_sha256': _sha(protocol),
        'runner_sha256': _sha(implementation),
        'dependency_sha256': dependency_hashes,
    }
    if commitment != expected_commitment:
        raise ValueError('Pre-scoring commitment mismatch')
    # Validate commitment before deserializing trusted-local joblib artifacts.
    models = {}
    for variant in ('original', 'corrected'):
        bundle, metadata = load_binary(model / variant)
        info = provenance['variants'][variant]
        if (metadata['variant'] != variant or metadata['bundle_sha256'] != info['bundle_sha256']
                or metadata['threshold'] != info['threshold']):
            raise ValueError('Frozen model disagrees with provenance')
        models[variant] = bundle
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='.ids2018-robustness-', dir=output.parent))
    try:
        quality = {}
        # Full preflight of both files before invoking either model.
        with (stage / 'exclusions.csv').open('x', encoding='utf-8', newline='') as stream:
            writer = csv.writer(stream)
            writer.writerow(['file', 'record_ordinal', 'reason'])
            for name in FILES:
                counts = Counter()
                label_counts = Counter()
                for ordinal, values, label, reason in _read_rows(data / name):
                    counts['records'] += 1
                    if reason:
                        counts[reason] += 1
                        writer.writerow([name, ordinal, reason])
                        continue
                    counts['eligible'] += 1
                    label_counts[label] += 1
                    counts['feature_group_matches_frozen'] += int(feature_digest(values) in blocked)
                quality[name] = {'counts': dict(counts), 'label_support': dict(sorted(label_counts.items()))}
        # No model receives rows until both complete files pass schema and label checks.
        counts = {variant: {name: Counter() for name in FILES} for variant in models}
        slices = {variant: {name: defaultdict(Counter) for name in FILES} for variant in models}
        for name in FILES:
            batch, batch_labels = [], []
            def score_batch():
                if not batch:
                    return
                matrix = np.asarray(batch, dtype=np.float64)
                for variant, bundle in models.items():
                    scores = attack_scores(bundle['binary_pipeline'], matrix)
                    if len(scores) != len(batch) or not np.all(np.isfinite(scores)) or np.any((scores < 0) | (scores > 1)):
                        raise ValueError('Invalid model scores')
                    for label, score in zip(batch_labels, scores):
                        positive = LABELS[label] == 1
                        predicted = bool(score >= bundle['threshold'])
                        key = 'tp' if positive and predicted else 'fn' if positive else 'fp' if predicted else 'tn'
                        counts[variant][name][key] += 1
                        counts[variant][name]['zero_score'] += int(score == 0)
                        slices[variant][name][label]['support'] += 1
                        slices[variant][name][label]['predicted_attack'] += int(predicted)
                batch.clear()
                batch_labels.clear()
            for _, values, label, reason in _read_rows(data / name):
                if reason:
                    continue
                batch.append(values)
                batch_labels.append(label)
                if len(batch) == batch_size:
                    score_batch()
            score_batch()
        results = {}
        for variant in models:
            aggregate = Counter()
            pooled_labels = defaultdict(Counter)
            results[variant] = {}
            for name in FILES:
                counts_for_day = counts[variant][name]
                if sum(counts_for_day[k] for k in ('tp', 'fp', 'tn', 'fn')) != quality[name]['counts'].get('eligible', 0):
                    raise ValueError('Scored row accounting mismatch')
                aggregate.update(counts_for_day)
                for label, counts_for_label in slices[variant][name].items():
                    pooled_labels[label].update(counts_for_label)
                results[variant][name] = {'metrics': _metrics(counts_for_day),
                    'per_label': {k: dict(v) for k, v in sorted(slices[variant][name].items())}}
            results[variant]['pooled'] = {'metrics': _metrics(aggregate),
                'per_label': {k: dict(v) for k, v in sorted(pooled_labels.items())}}
        if (_sha(commitment_file) != commitment_hash
                or _sha(protocol) != commitment['protocol_sha256']
                or _sha(implementation) != commitment['runner_sha256']
                or any(_sha(root / name) != digest for name, digest in dependency_hashes.items())
                or any(_sha(data / (name + '.acquisition.json')) != acquisition_hashes[name] for name in FILES)
                or _sha(split) != expected_split
                or any(_sha(data / name) != data_hashes[name] for name in FILES)
                or any(_sha(model / rel) != digest for rel, digest in model_hashes.items())
                or any(_sha(source / rel) != digest for rel, digest in provenance['source_files'].items())):
            raise ValueError('Input changed during evaluation')
        report = {'schema_version': 1, 'scope': 'Exploratory cross-capture cross-version robustness; supplied labels, no tuning.',
                  'quality': quality, 'results': results, 'data_sha256': data_hashes,
                  'model_sha256': model_hashes, 'acquisition_sha256': acquisition_hashes,
                  'pre_scoring_commitment_sha256': commitment_hash,
                  'frozen_splits_sha256': expected_split,
                  'limitations': 'Feature semantics and units provisional; labels may be wrong; two dependent days do not support temporal-block intervals. Equal feature vectors are not flow identity.'}
        (stage / 'results.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        stage.rename(output)
    except BaseException:
        shutil.rmtree(stage)
        raise
    return output
