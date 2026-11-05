"""Binary operating-point evaluation without test-set threshold tuning."""

from __future__ import annotations

import math

import numpy as np
from sklearn.metrics import average_precision_score


def _inputs(labels, scores):
    labels = np.asarray(labels)
    scores = np.asarray(scores, dtype=float)
    if labels.ndim != 1 or scores.ndim != 1 or len(labels) != len(scores):
        raise ValueError("labels and scores must be equal-length one-dimensional arrays")
    if not np.all(np.isin(labels, [0, 1])):
        raise ValueError("labels must contain only binary values 0 and 1")
    if not np.all(np.isfinite(scores)) or np.any((scores < 0) | (scores > 1)):
        raise ValueError("scores must be finite probabilities in [0, 1]")
    return labels.astype(int), scores


def _ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def _wilson(successes, total):
    if total == 0:
        return None
    z = 1.959963984540054
    p = successes / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return [max(0.0, center - half), min(1.0, center + half)]


def binary_metrics(labels, scores, threshold, record_ids, alert_budget=100):
    """Evaluate fixed scores; stable string record IDs break tied top-K scores.

    PR-AUC is specifically average precision, not trapezoidal PR integration.
    Wilson intervals treat flows as independent Bernoulli trials and do not
    account for temporal dependence; comparison block intervals are separate.
    """
    labels, scores = _inputs(labels, scores)
    if not isinstance(threshold, (int, float, np.number)) or not math.isfinite(threshold):
        raise ValueError("threshold must be finite")
    try:
        ids = list(record_ids)
    except TypeError as exc:
        raise ValueError("record_ids must contain one nonempty string per score") from exc
    if len(ids) != len(labels) or any(not isinstance(item, str) or not item for item in ids):
        raise ValueError("record_ids must contain one nonempty string per score")
    if len(set(ids)) != len(ids):
        raise ValueError("record_ids must be unique")
    if type(alert_budget) is not int or alert_budget <= 0:
        raise ValueError("alert_budget must be a positive integer")
    predicted = scores >= threshold
    positive = labels == 1
    tp = int(np.sum(predicted & positive))
    fp = int(np.sum(predicted & ~positive))
    tn = int(np.sum(~predicted & ~positive))
    fn = int(np.sum(~predicted & positive))
    k = min(alert_budget, len(labels))
    ranked = sorted(range(len(scores)), key=lambda i: (-float(scores[i]), ids[i]))
    top_hits = sum(int(labels[i]) for i in ranked[:k])
    return {
        "threshold": float(threshold),
        "support": {"benign": tn + fp, "attack": tp + fn, "total": len(labels)},
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "alert_count": tp + fp,
        "fpr": _ratio(fp, fp + tn),
        "recall": _ratio(tp, tp + fn),
        "precision": _ratio(tp, tp + fp),
        "pr_auc": float(average_precision_score(labels, scores)) if tp + fn else None,
        "pr_auc_method": "average_precision",
        "precision_at_k": _ratio(top_hits, k),
        "alert_budget": alert_budget,
        "k": k,
        "top_k_policy": "k=min(alert_budget,total); score descending, stable record_id ascending",
        "fpr_interval_95": _wilson(fp, fp + tn),
        "recall_interval_95": _wilson(tp, tp + fn),
        "interval_method": "Wilson 95%; flow independence assumed; temporal dependence not modeled",
    }


def select_threshold(labels, scores, fpr_target=0.01):
    """Choose an operating point in O(n log n), scanning tied scores together.

    Thresholds use score >= threshold. At equal recall, fewer alerts win;
    remaining ties prefer a higher threshold. No useful permitted detection
    returns the all-negative operating point and feasible/useful=False.
    Returned validation ranking metrics use positional IDs; recompute with
    actual record IDs before publishing precision@K from tied scores.
    """
    labels, scores = _inputs(labels, scores)
    if not isinstance(fpr_target, (int, float, np.number)) or not math.isfinite(fpr_target) or not 0 <= fpr_target <= 1:
        raise ValueError("fpr_target must lie in [0, 1]")
    benign = int(np.sum(labels == 0))
    attacks = int(np.sum(labels == 1))
    if not benign or not attacks:
        raise ValueError("Threshold selection requires both benign and attack validation support")
    none_threshold = float(np.nextafter(float(np.max(scores)), math.inf))
    best_threshold = none_threshold
    best_key = (0, 0, none_threshold)
    order = np.argsort(-scores, kind="stable")
    tp = fp = position = 0
    while position < len(order):
        score = float(scores[order[position]])
        stop = position
        while stop < len(order) and float(scores[order[stop]]) == score:
            if labels[order[stop]]:
                tp += 1
            else:
                fp += 1
            stop += 1
        if fp / benign <= fpr_target:
            key = (tp, -(tp + fp), score)
            if key > best_key:
                best_key = key
                best_threshold = score
        position = stop
    metrics = binary_metrics(labels, scores, best_threshold, [str(i) for i in range(len(labels))])
    useful = metrics["confusion"]["tp"] > 0
    return {
        "threshold": best_threshold,
        "feasible": useful,
        "useful": useful,
        "fpr_constraint_satisfied": metrics["fpr"] <= fpr_target,
        "fpr_target": float(fpr_target),
        "status": "useful_operating_point" if useful else "infeasible_useful_detection",
        "validation_metrics": metrics,
    }


def attack_scores(model, features):
    """Extract P(attack) by class identity, including constant benign baselines."""
    classes = list(model.classes_)
    if not classes or any(value not in (0, 1) for value in classes) or len(set(classes)) != len(classes):
        raise ValueError("Binary model classes_ must contain distinct 0 and/or 1 labels")
    probabilities = np.asarray(model.predict_proba(features), dtype=float)
    if probabilities.ndim != 2 or probabilities.shape != (len(features), len(classes)):
        raise ValueError("predict_proba shape does not match samples and classes_")
    if not np.all(np.isfinite(probabilities)) or np.any((probabilities < 0) | (probabilities > 1)):
        raise ValueError("predict_proba returned invalid probabilities")
    if not np.allclose(probabilities.sum(axis=1), 1.0):
        raise ValueError("predict_proba rows must sum to one")
    return probabilities[:, classes.index(1)] if 1 in classes else np.zeros(len(features))
