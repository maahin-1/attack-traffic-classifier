import numpy as np

from scripts.sensitivity_experiment007 import add_counts


def test_weighting_distinguishes_rows_groups_and_conflicting_rows():
    labels = np.array([0, 1, 0, 1])
    predicted = np.array([True, True, False, False])
    weights = np.array([10, 20, 30, 40])
    conflict = np.array([True, True, False, False])
    def count(w):
        result = dict.fromkeys(('tp', 'fp', 'tn', 'fn'), 0)
        add_counts(result, labels, predicted, w)
        return result
    assert count(weights) == {'tp': 20, 'fp': 10, 'tn': 30, 'fn': 40}
    assert count(np.ones(4, dtype=np.int64)) == {'tp': 1, 'fp': 1, 'tn': 1, 'fn': 1}
    assert count(weights * ~conflict) == {'tp': 0, 'fp': 0, 'tn': 30, 'fn': 40}
