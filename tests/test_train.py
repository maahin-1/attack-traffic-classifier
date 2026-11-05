"""Small CPU integration experiments exercising persisted training contracts."""

import copy
import csv
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from attack_traffic.model import load_model, score_model
from attack_traffic.train import run_experiment


class TrainingTests(unittest.TestCase):
    def setUp(self):
        self.repo = Path(__file__).resolve().parent.parent
        scratch = self.repo / ".test-tmp"
        scratch.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = json.loads((self.repo / "configs" / "demo.json").read_text())
        self.config["profile"] = "synthetic"
        self.config["output_dir"] = "experiment"
        self.config["datasets"] = self.config["datasets"][:1]
        self.config["datasets"][0]["files"] = ["flows.csv"]
        self.config["training"] = {
            "seed": 17, "n_estimators": 8, "max_depth": 3,
            "min_samples_leaf": 1, "n_jobs": 1,
            "max_rows_per_variant": 100, "fpr_target": .01, "alert_budget": 3,
        }
        self.rows = []
        for day in (1, 2, 3):
            for hour, attack in ((8, False), (9, True), (10, False), (11, True)):
                label = "UNSEEN" if day == 3 and attack else "ATTACK" if attack else "BENIGN"
                self.rows.append({
                    "Timestamp": f"2026-01-0{day} {hour:02}:00:00",
                    "End": f"2026-01-0{day} {hour:02}:00:01",
                    "Label": label,
                    "Duration": str(1000 + day * 100 + hour),
                    "Packets": str((100 if attack else 0) + day * 2 + hour),
                })
        self.write_rows()

    def write_rows(self):
        self.write_csv(self.root / "flows.csv", list(self.rows[0]), self.rows)

    @staticmethod
    def write_csv(path, fields, rows):
        with path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    @staticmethod
    def read_csv(path):
        with path.open(newline="", encoding="utf-8") as stream:
            return list(csv.DictReader(stream))

    def run_training(self):
        path = self.root / "config.json"
        path.write_text(json.dumps(self.config), encoding="utf-8")
        return run_experiment(path)

    def test_complete_run_contains_required_artifacts_and_frozen_threshold(self):
        output = self.run_training()
        for name in ("manifest.json", "config.json", "metrics.json", "predictions.csv", "per_class.csv", "report.md", "model_card.md", "audit/splits.csv", "audit/quality.json", "audit/retained_features.csv", "models/original/metadata.json", "models/original/bundle.joblib"):
            self.assertTrue((output / name).is_file(), name)
        metrics = json.loads((output / "metrics.json").read_text())["original"]
        self.assertEqual(set(metrics), {"baseline", "random_forest"})
        threshold = metrics["random_forest"]["threshold_policy"]["threshold"]
        metadata = json.loads((output / "models/original/metadata.json").read_text())
        self.assertEqual(metadata["threshold"], threshold)
        for row in self.read_csv(output / "predictions.csv"):
            if row["model"] == "random_forest":
                self.assertEqual(float(row["threshold"]), threshold)

    def test_saved_scoring_matches_original_test_predictions(self):
        output = self.run_training()
        expected = {
            row["record_id"]: row for row in self.read_csv(output / "predictions.csv")
            if row["model"] == "random_forest" and row["partition"] == "test"
        }
        features = [
            {key: row[key] for key in ("record_id", "flow_duration", "packet_count")}
            for row in self.read_csv(output / "audit/retained_features.csv") if row["record_id"] in expected
        ]
        self.write_csv(self.root / "score-input.csv", ["record_id", "flow_duration", "packet_count"], features)
        result = score_model(output / "models/original", self.root / "score-input.csv", self.root / "scores.csv")
        actual = self.read_csv(result)
        self.assertEqual(len(actual), len(expected))
        for row in actual:
            reference = expected[row["record_id"]]
            self.assertAlmostEqual(float(row["attack_score"]), float(reference["attack_score"]), places=14)
            for field in ("prediction", "class_prediction", "threshold", "model_id"):
                self.assertEqual(row[field], reference[field])

    def test_threshold_does_not_depend_on_test_features_or_labels(self):
        first = self.run_training()
        first_metrics = json.loads((first / "metrics.json").read_text())["original"]
        self.config["output_dir"] = "changed-test-experiment"
        for number, row in enumerate(self.rows):
            if row["Timestamp"].startswith("2026-01-03"):
                row["Label"] = "BENIGN"
                row["Packets"] = str(1000 + number)
                row["Duration"] = str(9000 + number)
        self.write_rows()
        second = self.run_training()
        second_metrics = json.loads((second / "metrics.json").read_text())["original"]
        for model in ("baseline", "random_forest"):
            self.assertEqual(first_metrics[model]["threshold_policy"]["threshold"], second_metrics[model]["threshold_policy"]["threshold"])
        self.assertIsNone(second_metrics["random_forest"]["test"]["recall"])

    def test_missing_binary_support_prevents_publication(self):
        original_rows = copy.deepcopy(self.rows)
        for day, partition in ((1, "train"), (2, "validation")):
            with self.subTest(partition=partition):
                self.rows = copy.deepcopy(original_rows)
                for row in self.rows:
                    if row["Timestamp"].startswith(f"2026-01-0{day}"):
                        row["Label"] = "BENIGN"
                self.write_rows()
                with self.assertRaisesRegex(ValueError, partition):
                    self.run_training()
                self.assertFalse((self.root / "experiment").exists())
                self.assertFalse(list(self.root.glob(".experiment-*")))

    def test_invalid_score_inputs_leave_no_partial_output(self):
        output = self.run_training()
        cases = [
            (["flow_duration", "packet_count"], [{"flow_duration": "NaN", "packet_count": 3}]),
            (["flow_duration"], [{"flow_duration": 1}]),
            (["flow_duration", "packet_count", "source_ip"], [{"flow_duration": 1, "packet_count": 3, "source_ip": "192.0.2.1"}]),
            (["flow_duration", "packet_count"], [{"flow_duration": 1, "packet_count": 3}, {"flow_duration": 2, "packet_count": "Infinity"}]),
        ]
        for fields, rows in cases:
            with self.subTest(fields=fields, rows=rows):
                self.write_csv(self.root / "score-input.csv", fields, rows)
                with self.assertRaises(ValueError):
                    score_model(output / "models/original", self.root / "score-input.csv", self.root / "scores.csv")
                self.assertFalse((self.root / "scores.csv").exists())
                self.assertFalse(list(self.root.glob(".scores-*")))

    def test_metadata_mismatch_is_rejected_before_deserialization(self):
        output = self.run_training()
        directory = output / "models/original"
        path = directory / "metadata.json"
        original = json.loads(path.read_text())
        for field, bad_value in (("schema_version", 999), ("environment", {}), ("bundle_sha256", "0" * 64), ("feature_allowlist", ["source_ip"])):
            with self.subTest(field=field):
                metadata = copy.deepcopy(original)
                metadata[field] = bad_value
                path.write_text(json.dumps(metadata), encoding="utf-8")
                with patch("attack_traffic.model.joblib.load") as deserialize:
                    with self.assertRaises(ValueError):
                        load_model(directory)
                    deserialize.assert_not_called()

    def test_row_cap_prevents_unbounded_training_and_publication(self):
        self.config["training"]["max_rows_per_variant"] = 2
        with self.assertRaisesRegex(ValueError, "max_rows_per_variant"):
            self.run_training()
        self.assertFalse((self.root / "experiment").exists())
        self.assertFalse(list(self.root.glob(".experiment-*")))

    def test_unseen_family_has_explicit_training_support_and_detection_recall(self):
        output = self.run_training()
        per_class = self.read_csv(output / "per_class.csv")
        unseen = next(row for row in per_class if row["model"] == "random_forest" and row["family"] == "synthetic_unseen")
        self.assertEqual(unseen["training_support"], "0")
        self.assertEqual(unseen["test_support"], "2")
        self.assertEqual(unseen["seen_in_training"], "False")
        self.assertEqual(float(unseen["family_attribution_recall"]), 0)
        self.assertIn(float(unseen["binary_detection_recall"]), [0, .5, 1])
        metrics = json.loads((output / "metrics.json").read_text())["original"]["random_forest"]["test"]
        self.assertEqual(metrics["unseen_attack_support"], 2)
        self.assertEqual(metrics["unseen_attack_recall"], float(unseen["binary_detection_recall"]))

    def test_fixed_seed_reproduces_scores(self):
        first = self.run_training()
        self.config["output_dir"] = "repeat-experiment"
        second = self.run_training()
        def stable_predictions(path):
            return [
                {key: row[key] for key in ("record_id", "model", "attack_score", "threshold", "prediction", "class_prediction")}
                for row in self.read_csv(path / "predictions.csv")
            ]
        self.assertEqual(stable_predictions(first), stable_predictions(second))

    def test_malformed_run_config_is_rejected_without_partial_run(self):
        original = copy.deepcopy(self.config)
        cases = [
            ("datasets", None), ("datasets", []), ("datasets", [None]),
            ("training", None), ("feature_units", None),
        ]
        for field, value in cases:
            with self.subTest(field=field, value=value):
                self.config = copy.deepcopy(original)
                self.config[field] = value
                with self.assertRaises(ValueError):
                    self.run_training()
                self.assertFalse((self.root / "experiment").exists())
                self.assertFalse(list(self.root.glob(".experiment-*")))
        for value in (None, [], [None]):
            with self.subTest(files=value):
                self.config = copy.deepcopy(original)
                self.config["datasets"][0]["files"] = value
                with self.assertRaises(ValueError):
                    self.run_training()
                self.assertFalse((self.root / "experiment").exists())
        self.config = copy.deepcopy(original)
        del self.config["datasets"][0]["files"]
        with self.assertRaises(ValueError):
            self.run_training()

    def test_score_rejects_duplicate_and_empty_provided_record_ids(self):
        output = self.run_training()
        for identifiers in (("same", "same"), ("", "second"), ("   ", "second")):
            with self.subTest(identifiers=identifiers):
                rows = [{"record_id": identifier, "flow_duration": 1000 + i, "packet_count": 10 + i} for i, identifier in enumerate(identifiers)]
                self.write_csv(self.root / "score-input.csv", ["record_id", "flow_duration", "packet_count"], rows)
                with self.assertRaisesRegex(ValueError, "(?i)(record|identifier|duplicate)"):
                    score_model(output / "models/original", self.root / "score-input.csv", self.root / "scores.csv")
                self.assertFalse((self.root / "scores.csv").exists())
                self.assertFalse(list(self.root.glob(".scores-*")))

    def test_score_rejects_duplicate_ids_across_batch_boundary(self):
        output = self.run_training()
        rows = [{"record_id": str(i), "flow_duration": 1000 + i, "packet_count": 10 + i} for i in range(1001)]
        rows[-1]["record_id"] = rows[0]["record_id"]
        self.write_csv(self.root / "score-input.csv", ["record_id", "flow_duration", "packet_count"], rows)
        with self.assertRaisesRegex(ValueError, "(?i)(record|identifier|duplicate)"):
            score_model(output / "models/original", self.root / "score-input.csv", self.root / "scores.csv")
        self.assertFalse((self.root / "scores.csv").exists())
        self.assertFalse(list(self.root.glob(".scores-*")))


if __name__ == "__main__":
    unittest.main()
