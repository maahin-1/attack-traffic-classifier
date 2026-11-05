"""Descriptive, post-evaluation shift audit. Never fit or adjust a model."""
import json
import shutil
import tempfile
from collections import Counter
from pathlib import Path

import numpy as np

from .evaluate import attack_scores
from .freeze_binary import load_binary
from .ids2018_robustness import FILES, LABELS, _read_rows
from .prepare import FEATURES
from .tune import _json, _load_cohorts, _sha

NAMES = [value[0] for value in FEATURES.values()]


def _outside_fraction(count, population):
    """An absent external class has no estimable range-violation fraction."""
    return float(count / population) if population else None


class Summary:
    """Exact moments/counts plus a bounded uniform random-priority reservoir."""
    def __init__(self, capacity=4096, seed=42):
        self.capacity = capacity
        self.rng = np.random.default_rng(seed)
        self.n = 0
        self.low = np.full(27, np.inf)
        self.high = np.full(27, -np.inf)
        self.total = np.zeros(27)
        self.zeros = np.zeros(27, dtype=np.int64)
        self.negative = np.zeros(27, dtype=np.int64)
        self.sample = np.empty((0, 27))
        self.priorities = np.empty(0)

    def add(self, rows):
        rows = np.asarray(rows, dtype=np.float64)
        if not len(rows):
            return
        if rows.ndim != 2 or rows.shape[1] != 27 or not np.all(np.isfinite(rows)):
            raise ValueError('Expected finite canonical 27-feature matrix')
        self.n += len(rows)
        self.low = np.minimum(self.low, rows.min(axis=0))
        self.high = np.maximum(self.high, rows.max(axis=0))
        self.total += rows.sum(axis=0)
        self.zeros += (rows == 0).sum(axis=0)
        self.negative += (rows < 0).sum(axis=0)
        priorities = np.concatenate((self.priorities, self.rng.random(len(rows))))
        sample = np.concatenate((self.sample, rows))
        keep = np.argsort(priorities, kind='stable')[:self.capacity]
        self.priorities, self.sample = priorities[keep], sample[keep]

    def export(self):
        if not self.n:
            return {'rows': 0, 'features': {}}
        quantiles = np.quantile(self.sample, [.01, .5, .99], axis=0)
        return {'rows': self.n, 'reservoir_rows': len(self.sample), 'features': {
            name: {'minimum': float(self.low[i]), 'maximum': float(self.high[i]),
                   'mean': float(self.total[i] / self.n), 'zero_fraction': float(self.zeros[i] / self.n),
                   'negative_count': int(self.negative[i]),
                   'approx_p01': float(quantiles[0, i]), 'approx_median': float(quantiles[1, i]),
                   'approx_p99': float(quantiles[2, i])} for i, name in enumerate(NAMES)}}


def run_shift_audit(source_run, data_dir, model_dir, evaluation_dir, output_dir):
    source, data, model, evaluation, output = map(Path, (source_run, data_dir, model_dir, evaluation_dir, output_dir))
    if output.exists():
        raise ValueError('Output already exists')
    expected = _json(evaluation / 'results.json')
    model_provenance = _json(model / 'provenance.json')
    inputs = {str(evaluation / 'results.json'): _sha(evaluation / 'results.json')}
    for name, digest in expected['data_sha256'].items():
        if _sha(data / name) != digest:
            raise ValueError('Evaluation input changed')
        inputs[str(data / name)] = digest
    for name, digest in expected['model_sha256'].items():
        if _sha(model / name) != digest:
            raise ValueError('Frozen model changed')
        inputs[str(model / name)] = digest
    for name, digest in model_provenance['source_files'].items():
        if _sha(source / name) != digest:
            raise ValueError('Frozen source changed')
        inputs[str(source / name)] = digest
    cohorts, _ = _load_cohorts(source, _json(source / 'config.json'), _json(source / 'manifest.json'))
    summaries, reference_ranges, scores_by_day, outside = {}, {}, {}, {}
    def summary(key):
        return summaries.setdefault(key, Summary())
    for variant, cohort in cohorts.items():
        for part in ('train', 'validation'):
            for label in (0, 1):
                rows = cohort['matrix'][cohort[part] & (cohort['labels'] == label)]
                summary(f'{variant}/{part}/{label}').add(rows)
                if part == 'train':
                    reference_ranges[(variant, label)] = (rows.min(axis=0), rows.max(axis=0))
    models = {v: load_binary(model / v)[0] for v in ('original', 'corrected')}
    importances = {v: dict(zip(NAMES, map(float, b['binary_pipeline'].named_steps['classifier'].feature_importances_))) for v, b in models.items()}
    for name in FILES:
        day = name.split('_')[0]
        confusion = {v: Counter() for v in models}
        zero_labels = {v: Counter() for v in models}
        rows, labels = [], []
        def batch():
            if not rows:
                return
            matrix, binary = np.asarray(rows), np.asarray(labels)
            for label in (0, 1):
                subset = matrix[binary == label]
                summary(f'2018/{day}/{label}').add(subset)
                for variant in models:
                    low, high = reference_ranges[(variant, label)]
                    key = f'{variant}/{day}/{label}'
                    outside.setdefault(key, np.zeros(27, dtype=np.int64))
                    outside[key] += ((subset < low) | (subset > high)).sum(axis=0)
            for variant, bundle in models.items():
                scores = attack_scores(bundle['binary_pipeline'], matrix)
                predicted = scores >= bundle['threshold']
                if not np.all(np.isfinite(scores)):
                    raise ValueError('Nonfinite model score')
                for label in (0, 1):
                    mask = binary == label
                    zero_labels[variant][str(label)] += int(np.sum((scores == 0) & mask))
                confusion[variant].update(tp=int(np.sum(predicted & (binary == 1))),
                    fp=int(np.sum(predicted & (binary == 0))), tn=int(np.sum(~predicted & (binary == 0))),
                    fn=int(np.sum(~predicted & (binary == 1))), zero_score=int(np.sum(scores == 0)))
                summary(f'{variant}/{day}/false_positive').add(matrix[predicted & (binary == 0)])
                summary(f'{variant}/{day}/true_negative').add(matrix[~predicted & (binary == 0)])
            rows.clear()
            labels.clear()
        for _, values, label, reason in _read_rows(data / name):
            if reason:
                continue
            rows.append(values)
            labels.append(LABELS[label])
            if len(rows) == 8192:
                batch()
        batch()
        for variant in models:
            previous = expected['results'][variant][name]['metrics']
            if any(confusion[variant][k] != previous[k] for k in ('tp', 'fp', 'tn', 'fn', 'zero_score')):
                raise ValueError('Rescoring differs from prior frozen assessment')
        scores_by_day[day] = {'confusion_parity': {v: dict(c) for v, c in confusion.items()},
                              'zero_scores_by_binary_label': {v: dict(c) for v, c in zero_labels.items()}}
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='.shift-', dir=output.parent))
    try:
        if any(_sha(Path(name)) != digest for name, digest in inputs.items()):
            raise ValueError('Inputs changed during diagnostic')
        exported = {key: s.export() for key, s in summaries.items()}
        comparisons = {}
        for key, counts in outside.items():
            variant, day, label = key.split('/')
            n = exported[f'2018/{day}/{label}']['rows']
            comparisons[key] = {name: {'outside_same_class_training_range_fraction': _outside_fraction(counts[i], n),
                'zero_fraction_difference_from_training': (exported[f'2018/{day}/{label}']['features'][name]['zero_fraction'] - exported[f'{variant}/train/{label}']['features'][name]['zero_fraction']) if n else None}
                for i, name in enumerate(NAMES)}
        result = {'schema_version': 1, 'scope': 'Post-evaluation descriptive diagnostic; no model fitting, threshold changes or new holdout.',
            'summary_method': 'Counts, min/max, means, zero/negative counts and outside-range fractions use the full population; arithmetic means and fractions are subject to floating-point rounding. Absent classes have null comparison fractions. Quantiles approximate from uniform random-priority reservoir of at most 4096 rows per group, numpy RNG seed42. Quantile estimates have sampling error. No saturation threshold imposed: maxima and p99 reported.',
            'binary_labels': {'0': 'supplied benign', '1': 'supplied attack'}, 'summaries': exported,
            'comparisons': comparisons, 'score_parity': scores_by_day, 'impurity_feature_importance': importances,
            'input_sha256': inputs, 'implementation_sha256': _sha(Path(__file__)),
            'limitations': 'Feature aliases/units provisional; labels uncertain; class-conditional differences confound family composition, capture and extraction versions. Impurity importance is training-description only, biased toward variable features and not causal. FP/TN summaries do not prove a source of failure.'}
        (stage / 'diagnostic.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        stage.rename(output)
    except BaseException:
        shutil.rmtree(stage)
        raise
    return output
