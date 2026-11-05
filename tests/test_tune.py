"""Weight ablation cannot consult or fit against held-out test evidence."""

import copy
import csv
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
from sklearn.ensemble import RandomForestClassifier

from attack_traffic.train import run_experiment
from attack_traffic.tune import _select_candidate, run_weight_ablation


class WeightAblationTests(unittest.TestCase):
    def setUp(self):
        self.repo = Path(__file__).resolve().parent.parent
        scratch = self.repo / ".test-tmp"
        scratch.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = json.loads((self.repo / "configs/demo.json").read_text())
        self.config.update(output_dir="source", profile="synthetic")
        self.config["training"] = {"seed": 31, "n_estimators": 4, "max_depth": 3, "min_samples_leaf": 1, "n_jobs": 1, "max_rows_per_variant": 100, "fpr_target": .01, "alert_budget": 3}
        for dataset in self.config["datasets"]:
            dataset["files"] = [f"{dataset['variant']}.csv"]
            rows = []
            for day in (1, 2, 3):
                for hour, attack in ((8, False), (9, True)):
                    rows.append({"Timestamp": f"2026-01-0{day} {hour:02}:00:00", "End": f"2026-01-0{day} {hour:02}:00:01", "Label": "ATTACK" if attack else "BENIGN", "Duration": str(day * 1000 + hour), "Packets": str(day * 100 + hour)})
            self.write_csv(self.root / dataset["files"][0], ["Timestamp", "End", "Label", "Duration", "Packets"], rows)
        path = self.root / "config.json"
        path.write_text(json.dumps(self.config), encoding="utf-8")
        self.source = run_experiment(path)
        self.output = self.root / "tuning"

    @staticmethod
    def write_csv(path, fields, rows):
        with path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    @staticmethod
    def read_csv(path):
        with path.open(newline="", encoding="utf-8") as stream:
            reader = csv.DictReader(stream)
            return reader.fieldnames, list(reader)

    @staticmethod
    def tree_hashes(directory):
        return {str(path.relative_to(directory)): hashlib.sha256(path.read_bytes()).hexdigest() for path in directory.rglob("*") if path.is_file()}

    def deny_test_scores(self):
        forbidden = {(self.source / name).resolve() for name in ("metrics.json", "predictions.csv")}
        actual_open = Path.open

        def checked_open(path, *args, **kwargs):
            if path.resolve() in forbidden:
                raise AssertionError(f"Tuning must not read saved test-score artifacts: {path.name}")
            return actual_open(path, *args, **kwargs)
        return patch.object(Path, "open", checked_open)

    def test_only_three_weight_candidates_fit_training_rows_and_preserve_source(self):
        before = self.tree_hashes(self.source)
        original_metrics = json.loads((self.source / "metrics.json").read_text())
        fit_calls = []
        actual_fit = RandomForestClassifier.fit

        def checked_fit(model, features, labels, *args, **kwargs):
            self.assertEqual(len(features), 2)
            self.assertTrue(np.all(np.asarray(features)[:, 0] < 2000))
            fit_calls.append(model.get_params())
            return actual_fit(model, features, labels, *args, **kwargs)

        with self.deny_test_scores(), patch.object(RandomForestClassifier, "fit", checked_fit), patch("joblib.load") as load:
            output = run_weight_ablation(self.source, self.output)
            load.assert_not_called()
        self.assertEqual(len(fit_calls), 6)
        self.assertEqual({str(call["class_weight"]) for call in fit_calls}, {"None", "balanced", "balanced_subsample"})
        normalized = [{key: value for key, value in call.items() if key != "class_weight"} for call in fit_calls]
        self.assertTrue(all(params == normalized[0] for params in normalized))
        self.assertEqual(self.tree_hashes(self.source), before)
        for name in ("candidate_metrics.json", "candidate_metrics.csv", "selection.json", "validation_predictions.csv", "per_class_validation.csv", "report.md", "provenance.json"):
            self.assertTrue((output / name).is_file(), name)
        result = json.loads((output / "candidate_metrics.json").read_text())
        self.assertEqual(result["candidate_order"], ["unweighted", "balanced", "balanced_subsample"])
        for variant in original_metrics:
            actual = result["candidates"]["unweighted"]["variants"][variant]["validation"]
            expected = original_metrics[variant]["random_forest"]["threshold_policy"]["validation_metrics"]
            for field in ("confusion", "support", "threshold", "recall", "fpr", "precision", "precision_at_k", "pr_auc"):
                self.assertEqual(actual[field], expected[field], (variant, field))

    def test_test_label_feature_and_saved_score_mutations_do_not_change_selection(self):
        with self.deny_test_scores():
            first = run_weight_ablation(self.source, self.output)
        expected_metrics = json.loads((first / "candidate_metrics.json").read_text())
        expected_selection = json.loads((first / "selection.json").read_text())
        path = self.source / "audit/splits.csv"
        headers, rows = self.read_csv(path)
        test_ids = set()
        for row in rows:
            if row["partition"] == "test":
                test_ids.add(row["record_id"])
                row.update(source_label="UNREAD-TEST-LABEL", family="UNREAD-TEST-FAMILY", binary_label="not-a-binary-label")
        self.write_csv(path, headers, rows)
        path = self.source / "audit/retained_features.csv"
        headers, rows = self.read_csv(path)
        for row in rows:
            if row["record_id"] in test_ids:
                row["flow_duration"] = "not-a-number"
                row["packet_count"] = "NaN"
        self.write_csv(path, headers, rows)
        for name in ("metrics.json", "predictions.csv"):
            (self.source / name).write_text("This test evidence must never be read", encoding="utf-8")
        with self.deny_test_scores():
            second = run_weight_ablation(self.source, self.root / "tuning-mutated-test")
        self.assertEqual(json.loads((second / "candidate_metrics.json").read_text()), expected_metrics)
        self.assertEqual(json.loads((second / "selection.json").read_text()), expected_selection)

    def test_validation_predictions_are_unique_and_reproduce_candidate_metrics(self):
        from attack_traffic.evaluate import binary_metrics
        with self.deny_test_scores():
            output = run_weight_ablation(self.source, self.output)
        metrics = json.loads((output / "candidate_metrics.json").read_text())["candidates"]
        _, predictions = self.read_csv(output / "validation_predictions.csv")
        keys = [(row["candidate"], row["variant"], row["record_id"]) for row in predictions]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertEqual(len(predictions), 12)
        self.assertTrue(all(row["partition"] == "validation" for row in predictions))
        for candidate in metrics:
            for variant, result in metrics[candidate]["variants"].items():
                rows = [row for row in predictions if row["candidate"] == candidate and row["variant"] == variant]
                measured = binary_metrics([int(row["binary_label"]) for row in rows], [float(row["attack_score"]) for row in rows], result["threshold_policy"]["threshold"], [row["record_id"] for row in rows], 3)
                for field, value in measured.items():
                    self.assertEqual(result["validation"][field], value)

    def test_existing_tuning_output_is_immutable(self):
        run_weight_ablation(self.source, self.output)
        before = self.tree_hashes(self.output)
        with self.assertRaises(ValueError):
            run_weight_ablation(self.source, self.output)
        self.assertEqual(self.tree_hashes(self.output), before)

    def test_invalid_train_validation_contracts_fail_atomically(self):
        path = self.source / "audit/splits.csv"
        original = path.read_bytes()
        fields, original_rows = self.read_csv(path)
        for case in ("binary", "label", "partition", "duplicate", "zero-benign-validation"):
            with self.subTest(case=case):
                rows = copy.deepcopy(original_rows)
                target = next(row for row in rows if row["partition"] == "train")
                if case == "binary":
                    target["binary_label"] = "2"
                elif case == "label":
                    target["source_label"] = "UNKNOWN"
                elif case == "partition":
                    target["partition"] = "unknown"
                elif case == "duplicate":
                    rows.append(copy.deepcopy(target))
                else:
                    for row in rows:
                        if row["partition"] == "validation":
                            row.update(source_label="ATTACK", binary_label="1", family="synthetic_attack")
                self.write_csv(path, fields, rows)
                with self.assertRaises(ValueError):
                    run_weight_ablation(self.source, self.output)
                self.assertFalse(self.output.exists())
                path.write_bytes(original)

    def test_invalid_feature_values_or_missing_duplicate_ids_fail_atomically(self):
        path = self.source / "audit/retained_features.csv"
        original = path.read_bytes()
        fields, original_rows = self.read_csv(path)
        for case in ("nonfinite", "missing", "duplicate"):
            with self.subTest(case=case):
                rows = copy.deepcopy(original_rows)
                if case == "nonfinite":
                    rows[0]["flow_duration"] = "NaN"
                elif case == "missing":
                    rows.pop(0)
                else:
                    rows.append(copy.deepcopy(rows[0]))
                self.write_csv(path, fields, rows)
                with self.assertRaises(ValueError):
                    run_weight_ablation(self.source, self.output)
                self.assertFalse(self.output.exists())
                path.write_bytes(original)

    def test_explicit_cohort_resource_cap_fails_without_partial_output(self):
        config_path, manifest_path = self.source / "config.json", self.source / "manifest.json"
        config = json.loads(config_path.read_text())
        manifest = json.loads(manifest_path.read_text())
        config["training"]["max_rows_per_variant"] = 3
        manifest["training"]["max_rows_per_variant"] = 3
        manifest["config_sha256"] = hashlib.sha256(json.dumps(config, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        config_path.write_text(json.dumps(config), encoding="utf-8")
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "max_rows_per_variant"):
            run_weight_ablation(self.source, self.output)
        self.assertFalse(self.output.exists())
        self.assertFalse(list(self.root.glob(".ablation-*")))

    def test_failed_candidate_is_recorded_without_partial_predictions_or_promotion(self):
        actual_fit = RandomForestClassifier.fit

        def candidate_failure(model, *args, **kwargs):
            if model.class_weight == "balanced":
                raise MemoryError("Synthetic candidate fitting failure")
            return actual_fit(model, *args, **kwargs)

        with patch.object(RandomForestClassifier, "fit", candidate_failure), self.deny_test_scores():
            output = run_weight_ablation(self.source, self.output)
        metrics = json.loads((output / "candidate_metrics.json").read_text())["candidates"]
        failed = metrics["balanced"]
        self.assertFalse(failed["eligible"])
        self.assertTrue(all(result["status"] == "failed" for result in failed["variants"].values()))
        self.assertTrue(all("MemoryError" in result["error"] for result in failed["variants"].values()))
        _, predictions = self.read_csv(output / "validation_predictions.csv")
        _, classes = self.read_csv(output / "per_class_validation.csv")
        self.assertFalse(any(row["candidate"] == "balanced" for row in predictions + classes))
        selection = json.loads((output / "selection.json").read_text())
        self.assertNotEqual(selection["best_candidate"], "balanced")
        self.assertNotEqual(selection["promoted_candidate"], "balanced")


class JointSelectionTests(unittest.TestCase):
    @staticmethod
    def candidates(specification):
        return {
            name: {"variants": {
                variant: {"status": "ok", "validation": {"recall": recall, "fpr": fpr}, "threshold_policy": {"fpr_target": .01}}
                for variant, (recall, fpr) in zip(("original", "corrected"), values)
            }} for name, values in specification.items()
        }

    def test_every_variant_must_meet_fpr_target(self):
        candidates = self.candidates({"unweighted": [(.2, .005), (.2, .005)], "balanced": [(.8, .02), (.8, 0)], "balanced_subsample": [(.3, .008), (.3, .008)]})
        result = _select_candidate(candidates)
        self.assertFalse(candidates["balanced"]["eligible"])
        self.assertEqual(result["best_candidate"], "balanced_subsample")
        self.assertEqual(result["promoted_candidate"], "balanced_subsample")

    def test_no_variant_recall_regression_is_required_for_promotion(self):
        candidates = self.candidates({"unweighted": [(.3, .005), (.3, .005)], "balanced": [(.8, .005), (.2, .005)], "balanced_subsample": [(.3, .005), (.3, .005)]})
        result = _select_candidate(candidates)
        self.assertEqual(result["best_candidate"], "balanced")
        self.assertEqual(result["promoted_candidate"], "unweighted")
        self.assertFalse(result["promotion_passed"])

    def test_recall_ties_prefer_lower_mean_fpr_then_fixed_order_but_do_not_promote(self):
        candidates = self.candidates({"unweighted": [(.2, .006), (.2, .006)], "balanced": [(.2, .005), (.2, .005)], "balanced_subsample": [(.2, .005), (.2, .005)]})
        result = _select_candidate(candidates)
        self.assertEqual(result["best_candidate"], "balanced")
        self.assertEqual(result["promoted_candidate"], "unweighted")
        self.assertFalse(result["promotion_passed"])

    def test_mean_recall_change_within_numeric_tolerance_does_not_promote(self):
        candidates = self.candidates({"unweighted": [(.2, .005), (.2, .005)], "balanced": [(.2 + 5e-13, .005), (.2 + 5e-13, .005)], "balanced_subsample": [(.2, .005), (.2, .005)]})
        result = _select_candidate(candidates)
        self.assertFalse(result["promotion_passed"])
        self.assertEqual(result["promoted_candidate"], "unweighted")

    def test_candidate_missing_a_reference_variant_cannot_win(self):
        candidates = self.candidates({"unweighted": [(.2, .005), (.2, .005)], "balanced": [(.9, .005), (.9, .005)], "balanced_subsample": [(.3, .005), (.3, .005)]})
        del candidates["balanced"]["variants"]["corrected"]
        result = _select_candidate(candidates)
        self.assertFalse(candidates["balanced"]["eligible"])
        self.assertNotEqual(result["best_candidate"], "balanced")
        self.assertEqual(result["best_candidate"], "balanced_subsample")
        self.assertEqual(result["promoted_candidate"], "balanced_subsample")


if __name__ == "__main__":
    unittest.main()
