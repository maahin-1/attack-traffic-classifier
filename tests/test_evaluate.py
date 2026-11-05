"""Hand-computed metric and threshold-policy regressions."""

import math
import unittest

import numpy as np

from attack_traffic.evaluate import attack_scores, binary_metrics, select_threshold


class MetricsTests(unittest.TestCase):
    def test_hand_computed_confusion_and_precision(self):
        result = binary_metrics([0, 1, 0, 1], [.9, .8, .2, .1], .5, ["a", "b", "c", "d"], 2)
        self.assertEqual(result["confusion"], {"tp": 1, "fp": 1, "tn": 1, "fn": 1})
        self.assertEqual(result["fpr"], .5)
        self.assertEqual(result["recall"], .5)
        self.assertEqual(result["precision"], .5)
        self.assertEqual(result["precision_at_k"], .5)
        self.assertEqual(result["pr_auc"], .5)
        self.assertEqual(result["pr_auc_method"], "average_precision")
        for field in ("fpr_interval_95", "recall_interval_95"):
            self.assertAlmostEqual(result[field][0], .0945312057)
            self.assertAlmostEqual(result[field][1], .9054687943)

    def test_stable_record_ids_break_tied_top_k_scores(self):
        result = binary_metrics([0, 1, 0], [.8, .8, .8], .8, ["c", "a", "b"], 1)
        self.assertEqual(result["precision_at_k"], 1)
        result = binary_metrics([0, 1, 0], [.8, .8, .8], .8, ["a", "c", "b"], 1)
        self.assertEqual(result["precision_at_k"], 0)

    def test_small_population_discloses_actual_k(self):
        result = binary_metrics([1, 0], [.9, .1], .5, ["a", "b"])
        self.assertEqual(result["alert_budget"], 100)
        self.assertEqual(result["k"], 2)
        self.assertEqual(result["precision_at_k"], .5)

    def test_null_denominators_are_visible(self):
        empty = binary_metrics([], [], .5, [])
        for field in ("fpr", "recall", "precision", "pr_auc", "precision_at_k", "fpr_interval_95", "recall_interval_95"):
            self.assertIsNone(empty[field], field)
        attacks_only = binary_metrics([1], [.9], .5, ["a"])
        self.assertIsNone(attacks_only["fpr"])
        self.assertIsNone(attacks_only["fpr_interval_95"])
        benign_only = binary_metrics([0], [.1], .5, ["a"])
        self.assertIsNone(benign_only["recall"])
        self.assertIsNone(benign_only["precision"])
        self.assertIsNone(benign_only["pr_auc"])

    def test_invalid_metric_inputs_fail_closed(self):
        cases = [
            ([0], [float("nan")], .5, ["a"], 100),
            ([0], [1.1], .5, ["a"], 100),
            ([0], [-.1], .5, ["a"], 100),
            ([2], [.5], .5, ["a"], 100),
            ([[0]], [[.5]], .5, ["a"], 100),
            ([0], [.5, .6], .5, ["a"], 100),
            ([0, 1], [.5, .6], .5, ["a", "a"], 100),
            ([0], [.5], .5, [""], 100),
            ([0], [.5], float("inf"), ["a"], 100),
            ([0], [.5], .5, ["a"], 0),
        ]
        for values in cases:
            with self.subTest(values=values), self.assertRaises(ValueError):
                binary_metrics(*values)


class ThresholdTests(unittest.TestCase):
    def test_maximizes_recall_under_fpr_ceiling(self):
        result = select_threshold([1, 1, 0, 1, 0], [.9, .8, .7, .6, .1], .5)
        self.assertEqual(result["threshold"], .6)
        self.assertEqual(result["validation_metrics"]["recall"], 1)
        self.assertEqual(result["validation_metrics"]["fpr"], .5)
        self.assertTrue(result["feasible"])

    def test_equal_recall_prefers_fewer_alerts_and_higher_threshold(self):
        result = select_threshold([1, 0, 0], [.9, .8, .1], 1)
        self.assertEqual(result["threshold"], .9)
        self.assertEqual(result["validation_metrics"]["alert_count"], 1)

    def test_tied_scores_are_indivisible_and_no_useful_detection_is_explicit(self):
        result = select_threshold([0, 1], [1.0, 1.0], 0)
        self.assertGreater(result["threshold"], 1.0)
        self.assertTrue(math.isfinite(result["threshold"]))
        self.assertFalse(result["feasible"])
        self.assertFalse(result["useful"])
        self.assertTrue(result["fpr_constraint_satisfied"])
        self.assertEqual(result["validation_metrics"]["alert_count"], 0)

    def test_both_binary_supports_required(self):
        for labels, scores in (([], []), ([0], [.5]), ([1], [.5])):
            with self.subTest(labels=labels), self.assertRaises(ValueError):
                select_threshold(labels, scores)

    def test_invalid_fpr_targets_rejected(self):
        for target in (-.1, 1.1, float("nan"), float("inf"), "0.01"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                select_threshold([0, 1], [.1, .9], target)

    def test_grouped_search_matches_exhaustive_policy(self):
        generator = np.random.default_rng(7)
        for _ in range(20):
            labels = np.concatenate(([0, 1], generator.integers(0, 2, size=30)))
            scores = generator.integers(0, 11, size=len(labels)) / 10
            target = .2
            candidates = [float(np.nextafter(max(scores), math.inf)), *sorted(set(scores), reverse=True)]
            ranked = []
            for threshold in candidates:
                predicted = scores >= threshold
                tp = int(np.sum(predicted & (labels == 1)))
                fp = int(np.sum(predicted & (labels == 0)))
                if fp / int(np.sum(labels == 0)) <= target:
                    ranked.append(((tp, -int(np.sum(predicted)), threshold), threshold))
            expected = max(ranked)[1]
            self.assertEqual(select_threshold(labels, scores, target)["threshold"], expected)


class ProbabilityTests(unittest.TestCase):
    def test_looks_up_attack_class_instead_of_assuming_column_one(self):
        class ReversedClasses:
            classes_ = np.array([1, 0])

            def predict_proba(self, features):
                return np.array([[.8, .2], [.1, .9]])

        np.testing.assert_array_equal(attack_scores(ReversedClasses(), [[1], [2]]), [.8, .1])

    def test_constant_benign_model_returns_zero_scores(self):
        class BenignOnly:
            classes_ = np.array([0])

            def predict_proba(self, features):
                return np.ones((len(features), 1))

        np.testing.assert_array_equal(attack_scores(BenignOnly(), [[1], [2]]), [0, 0])

    def test_invalid_probability_shapes_and_values_rejected(self):
        class InvalidModel:
            classes_ = np.array([0, 1])

            def predict_proba(self, features):
                return np.array([[.9, .9]])

        with self.assertRaises(ValueError):
            attack_scores(InvalidModel(), [[1]])


if __name__ == "__main__":
    unittest.main()
