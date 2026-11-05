"""Reports must verify saved evidence without fitting or deserializing models."""

import copy
import csv
import hashlib
import json
import math
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from attack_traffic.report import rebuild_report
from attack_traffic.train import run_experiment


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.repo = Path(__file__).resolve().parent.parent
        scratch = self.repo / ".test-tmp"
        scratch.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = json.loads((self.repo / "configs/demo.json").read_text())
        self.config["profile"] = "synthetic"
        self.config["output_dir"] = "run"
        self.config["training"] = {"seed": 19, "n_estimators": 4, "max_depth": 3, "min_samples_leaf": 1, "n_jobs": 1, "max_rows_per_variant": 100, "fpr_target": .01, "alert_budget": 3}
        for dataset in self.config["datasets"]:
            dataset["files"] = [str((self.repo / "configs" / source).resolve()) for source in dataset["files"]]
        self.run_dir = None
        self.output = self.root / "rebuilt"

    def train(self, corrected_only=True):
        config = copy.deepcopy(self.config)
        if corrected_only:
            config["datasets"] = config["datasets"][1:]
        path = self.root / "config.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        self.run_dir = run_experiment(path)
        return self.run_dir

    @staticmethod
    def csv_rows(path):
        with path.open(newline="", encoding="utf-8") as stream:
            reader = csv.DictReader(stream)
            return reader.fieldnames, list(reader)

    @staticmethod
    def write_csv(path, fields, rows):
        with path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    @staticmethod
    def tree_hashes(directory):
        return {str(path.relative_to(directory)): hashlib.sha256(path.read_bytes()).hexdigest() for path in directory.rglob("*") if path.is_file()}

    def rebuild(self):
        return rebuild_report(self.run_dir, self.output)

    def assert_no_output(self):
        self.assertFalse(self.output.exists())
        self.assertFalse(list(self.root.glob(".report-*")))

    def test_rebuild_preserves_metrics_without_training_or_model_loading(self):
        self.train()
        before = self.tree_hashes(self.run_dir)
        with patch("sklearn.ensemble.RandomForestClassifier.fit") as forest_fit, patch("sklearn.dummy.DummyClassifier.fit") as baseline_fit, patch("joblib.load") as deserialize:
            output = self.rebuild()
            forest_fit.assert_not_called()
            baseline_fit.assert_not_called()
            deserialize.assert_not_called()
        for name in ("report.md", "metrics.csv", "per_class.csv", "provenance.json"):
            self.assertTrue((output / name).is_file(), name)
        self.assertEqual(self.tree_hashes(self.run_dir), before)
        original = json.loads((self.run_dir / "metrics.json").read_text())
        rebuilt = json.loads((output / "metrics.json").read_text())
        for variant, models in original.items():
            for model, metrics in models.items():
                self.assertEqual(rebuilt[variant][model]["test"], metrics["test"])
                self.assertEqual(rebuilt[variant][model]["threshold_policy"]["validation_metrics"], metrics["threshold_policy"]["validation_metrics"])

    def test_corrected_only_report_does_not_claim_a_paired_comparison(self):
        self.train()
        output = self.rebuild()
        self.assertFalse((output / "comparison.csv").exists())
        text = (output / "report.md").read_text().lower()
        self.assertIn("corrected", text)
        self.assertTrue("single" in text or "unavailable" in text or "no paired" in text)
        provenance = json.loads((output / "provenance.json").read_text())
        self.assertFalse(provenance["controls"]["comparison_eligible"])

    def test_matched_two_variant_run_exports_population_comparison(self):
        self.train(corrected_only=False)
        output = self.rebuild()
        self.assertTrue((output / "comparison.csv").is_file())
        _, rows = self.csv_rows(output / "comparison.csv")
        self.assertTrue(rows)
        text = (output / "report.md").read_text().lower()
        self.assertIn("population", text)
        self.assertIn("label-only", text)
        provenance = json.loads((output / "provenance.json").read_text())
        self.assertTrue(provenance["controls"]["comparison_eligible"])

    def test_rebuild_output_is_immutable(self):
        self.train()
        output = self.rebuild()
        before = self.tree_hashes(output)
        with self.assertRaises(ValueError):
            self.rebuild()
        self.assertEqual(self.tree_hashes(output), before)

    def test_tampered_prediction_evidence_is_rejected(self):
        self.train()
        path = self.run_dir / "predictions.csv"
        original_bytes = path.read_bytes()
        fields, original = self.csv_rows(path)
        cases = ["missing", "duplicate", "nonfinite", "threshold", "model_id", "record_id", "schema", "decision", "source_label"]
        for case in cases:
            with self.subTest(case=case):
                rows = copy.deepcopy(original)
                headers = fields[:]
                if case == "missing":
                    rows.pop()
                elif case == "duplicate":
                    rows.append(copy.deepcopy(rows[0]))
                elif case == "schema":
                    headers.remove("attack_score")
                    for row in rows:
                        del row["attack_score"]
                else:
                    changes = {
                        "nonfinite": ("attack_score", "NaN"), "threshold": ("threshold", "0.123456"),
                        "model_id": ("model_id", "unrelated-model"), "record_id": ("record_id", "unknown-record"),
                        "decision": ("prediction", str(1 - int(rows[0]["prediction"]))),
                        "source_label": ("source_label", "forged-label"),
                    }
                    key, value = changes[case]
                    rows[0][key] = value
                self.write_csv(path, headers, rows)
                with self.assertRaises(ValueError):
                    self.rebuild()
                self.assert_no_output()
                path.write_bytes(original_bytes)

    def test_inconsistent_saved_metrics_are_rejected(self):
        self.train()
        path = self.run_dir / "metrics.json"
        metrics = json.loads(path.read_text())
        test = metrics["corrected"]["random_forest"]["test"]
        test["recall"] = 1.0 if test["recall"] != 1.0 else 0.0
        path.write_text(json.dumps(metrics), encoding="utf-8")
        with self.assertRaises(ValueError):
            self.rebuild()
        self.assert_no_output()

    def test_missing_required_source_artifact_is_rejected(self):
        self.train()
        (self.run_dir / "audit/splits.csv").unlink()
        with self.assertRaises(ValueError):
            self.rebuild()
        self.assert_no_output()

    def test_mismatched_time_controls_cannot_be_published_as_comparison(self):
        self.train(corrected_only=False)
        path = self.run_dir / "manifest.json"
        manifest = json.loads(path.read_text())
        manifest["boundaries"]["test_start"] = "2026-01-02T12:00:00+00:00"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaises(ValueError):
            self.rebuild()
        self.assert_no_output()

    def test_inconsistent_per_class_support_is_rejected(self):
        self.train()
        path = self.run_dir / "per_class.csv"
        headers, rows = self.csv_rows(path)
        unseen = next(row for row in rows if row["family"] == "synthetic_unseen" and row["model"] == "random_forest")
        unseen["training_support"] = "100"
        unseen["seen_in_training"] = "True"
        self.write_csv(path, headers, rows)
        with self.assertRaises(ValueError):
            self.rebuild()
        self.assert_no_output()

    def test_manifest_profile_cannot_hide_synthetic_run_warning(self):
        self.train()
        path = self.run_dir / "manifest.json"
        manifest = json.loads(path.read_text())
        manifest["profile"] = "full"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaises(ValueError):
            self.rebuild()
        self.assert_no_output()

    def test_full_profile_report_does_not_label_itself_a_deterministic_subset(self):
        self.config["profile"] = "full"
        self.train()
        output = self.rebuild()
        text = (output / "report.md").read_text().lower()
        self.assertNotIn("deterministic subset", text)

    def test_all_attacks_missed_does_not_print_zero_denominator_fraction(self):
        self.config["training"]["min_samples_leaf"] = 100
        self.train()
        metrics = json.loads((self.run_dir / "metrics.json").read_text())
        self.assertEqual(metrics["corrected"]["random_forest"]["test"]["recall"], 0)
        output = self.rebuild()
        text = (output / "report.md").read_text().lower()
        self.assertNotIn("0/0", text)
        self.assertIn("dominant detected family is undefined", text)

    def test_frozen_metric_threshold_requires_exact_consistency(self):
        self.train()
        path = self.run_dir / "metrics.json"
        original = path.read_bytes()
        for partition in ("test", "validation"):
            with self.subTest(partition=partition):
                metrics = json.loads(original)
                result = metrics["corrected"]["random_forest"]
                partition_metrics = result["test"] if partition == "test" else result["threshold_policy"]["validation_metrics"]
                partition_metrics["threshold"] = math.nextafter(partition_metrics["threshold"], math.inf)
                path.write_text(json.dumps(metrics), encoding="utf-8")
                with self.assertRaises(ValueError):
                    self.rebuild()
                self.assert_no_output()

    def test_optional_charts_and_parquet_keep_source_and_frozen_scores_unchanged(self):
        self.train(corrected_only=False)
        before = self.tree_hashes(self.run_dir)
        with patch("joblib.load") as deserialize, patch("sklearn.ensemble.RandomForestClassifier.fit") as fit:
            output = rebuild_report(self.run_dir, self.output, charts=True, parquet=True)
            deserialize.assert_not_called()
            fit.assert_not_called()
        self.assertEqual(self.tree_hashes(self.run_dir), before)
        provenance = json.loads((output / "provenance.json").read_text())
        optional = provenance["optional_outputs"]
        self.assertTrue(any(name.endswith(".png") for name in optional))
        self.assertTrue(any(name.endswith(".parquet") for name in optional))
        for name in optional:
            self.assertTrue((output / name).is_file(), name)
        expected = json.loads((self.run_dir / "metrics.json").read_text())
        actual = json.loads((output / "metrics.json").read_text())
        for variant in expected:
            for model in expected[variant]:
                self.assertEqual(actual[variant][model]["test"], expected[variant][model]["test"])


if __name__ == "__main__":
    unittest.main()
