"""Feature-collision diagnostics use complete eligible label populations."""

import copy
import csv
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from attack_traffic.collision_audit import audit_collisions
from attack_traffic.train import run_experiment


class CollisionAuditTests(unittest.TestCase):
    def setUp(self):
        self.repo = Path(__file__).resolve().parent.parent
        scratch = self.repo / ".test-tmp"
        scratch.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = json.loads((self.repo / "configs/demo.json").read_text())
        self.config.update(output_dir="source", profile="synthetic")
        self.config["label_map"]["PORTSCAN"] = {"binary": 1, "family": "Portscan"}
        self.config["training"] = {"seed": 29, "n_estimators": 4, "max_depth": 3, "min_samples_leaf": 1, "n_jobs": 1, "max_rows_per_variant": 100, "fpr_target": .01, "alert_budget": 3}
        fields = ["Timestamp", "End", "Label", "Duration", "Packets", "CaptureDate", "SourceTimestamp"]
        for dataset in self.config["datasets"]:
            dataset["files"] = [f"{dataset['variant']}.csv"]
            dataset["columns"].update(CaptureDate="capture_date", SourceTimestamp="source_timestamp")
            rows = []
            for day in (1, 2, 3):
                for hour, attack in ((8, False), (9, True)):
                    rows.append({"Timestamp": f"2026-01-0{day} {hour:02}:00:00", "End": f"2026-01-0{day} {hour:02}:00:01", "Label": "PORTSCAN" if day == 3 and attack else "ATTACK" if attack else "BENIGN", "Duration": str(day * 100 + hour), "Packets": str(day * 10 + hour)})
            for hour in (10, 11):
                rows.append({"Timestamp": f"2026-01-03 {hour}:00:00", "End": f"2026-01-03 {hour}:00:01", "Label": "PORTSCAN", "Duration": rows[0]["Duration"], "Packets": rows[0]["Packets"]})
            for row in rows:
                row["CaptureDate"] = row["Timestamp"][:10]
                row["SourceTimestamp"] = row["Timestamp"]
            self.write_csv(self.root / dataset["files"][0], fields, rows)
        config_path = self.root / "config.json"
        config_path.write_text(json.dumps(self.config), encoding="utf-8")
        self.source = run_experiment(config_path)
        self.output = self.root / "collisions"

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

    def test_complete_group_minority_bound_differs_from_first_label_conflict_count(self):
        before = self.tree_hashes(self.source)
        with patch("sklearn.ensemble.RandomForestClassifier.fit") as fit, patch("joblib.load") as load:
            output = audit_collisions(self.source, self.output)
            fit.assert_not_called()
            load.assert_not_called()
        for name in ("summary.json", "group_summary.csv", "class_losses.csv", "partition_support.csv", "report.md", "provenance.json"):
            self.assertTrue((output / name).is_file(), name)
        summary = json.loads((output / "summary.json").read_text())
        for variant in ("original", "corrected"):
            values = summary["variants"][variant]
            self.assertEqual(values["eligible_rows"], 8)
            self.assertEqual(values["feature_group_count"], 6)
            self.assertEqual(values["duplicate_group_count"], 1)
            self.assertEqual(values["binary_conflict_group_count"], 1)
            self.assertEqual(values["binary_conflict_group_rows"], 3)
            self.assertEqual(values["binary_minority_label_error_lower_bound"], 1)
            self.assertEqual(values["duplicate_conflicting_binary_label_rows"], 2)
            self.assertEqual(values["duplicate_conflicting_source_label_rows"], 2)
            self.assertEqual(values["cross_capture_date_group_count"], 1)
            self.assertEqual(values["differing_source_timestamp_group_count"], 1)
        self.assertEqual(self.tree_hashes(self.source), before)

    def test_portscan_losses_and_partition_support_are_visible(self):
        output = audit_collisions(self.source, self.output)
        _, losses = self.read_csv(output / "class_losses.csv")
        text = json.dumps(losses)
        self.assertIn("Portscan", text)
        _, groups = self.read_csv(output / "group_summary.csv")
        self.assertEqual(len(groups), 2)
        _, support = self.read_csv(output / "partition_support.csv")
        self.assertTrue(any(row["partition"] == "test" for row in support))
        for variant in ("original", "corrected"):
            selected = [row for row in losses if row["variant"] == variant and (row.get("family") == "Portscan" or row.get("source_label") == "PORTSCAN")]
            self.assertEqual(len(selected), 1)
            self.assertEqual(selected[0]["input_rows"], "3")
            self.assertEqual(selected[0]["retained_rows"], "1")
            self.assertEqual(selected[0]["later_duplicate_rows"], "2")
            self.assertAlmostEqual(float(selected[0]["loss_fraction"]), 2 / 3)
            portscan_test = next(row for row in support if row["variant"] == variant and row["partition"] == "test" and row["family"] == "Portscan")
            self.assertEqual(portscan_test["input_rows"], "3")
            self.assertEqual(portscan_test["retained_rows"], "1")
            self.assertEqual(portscan_test["quarantined_rows"], "2")
            group = next(row for row in groups if row["variant"] == variant)
            self.assertEqual(group["capture_date_count"], "2")
            self.assertEqual(group["source_timestamp_count"], "3")
            self.assertEqual(json.loads(group["partition_support"]), {"train": 1, "test": 2})

    def test_collision_output_is_immutable(self):
        audit_collisions(self.source, self.output)
        before = self.tree_hashes(self.output)
        with self.assertRaises(ValueError):
            audit_collisions(self.source, self.output)
        self.assertEqual(self.tree_hashes(self.output), before)

    def test_invalid_source_counts_are_rejected_without_publishing(self):
        path = self.source / "audit/quality.json"
        quality = json.loads(path.read_text())
        quality["original"]["input_rows"] += 1
        path.write_text(json.dumps(quality), encoding="utf-8")
        with self.assertRaises(ValueError):
            audit_collisions(self.source, self.output)
        self.assertFalse(self.output.exists())

    def test_tampered_feature_join_or_duplicate_record_ids_are_rejected(self):
        path = self.source / "audit/retained_features.csv"
        original = path.read_bytes()
        fields, original_rows = self.read_csv(path)
        for kind in ("value", "duplicate", "missing"):
            with self.subTest(kind=kind):
                rows = copy.deepcopy(original_rows)
                if kind == "value":
                    rows[0]["flow_duration"] = "999999"
                elif kind == "duplicate":
                    rows.append(copy.deepcopy(rows[0]))
                else:
                    rows.pop()
                self.write_csv(path, fields, rows)
                with self.assertRaises(ValueError):
                    audit_collisions(self.source, self.output)
                self.assertFalse(self.output.exists())
                path.write_bytes(original)


if __name__ == "__main__":
    unittest.main()
