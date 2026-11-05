"""Regression checks for the audited-data bridge into model training."""

import csv
import json
import math
from pathlib import Path
import tempfile
import unittest

from attack_traffic import run_audit
from attack_traffic.config import load_config


class AuditBridgeTests(unittest.TestCase):
    def setUp(self):
        self.repo = Path(__file__).resolve().parent.parent
        scratch = self.repo / ".test-tmp"
        scratch.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = json.loads((self.repo / "configs/demo.json").read_text())
        self.config["output_dir"] = "audit"
        for dataset in self.config["datasets"]:
            dataset["files"] = [str((self.repo / "configs" / file).resolve()) for file in dataset["files"]]

    def run_audit(self):
        path = self.root / "config.json"
        path.write_text(json.dumps(self.config), encoding="utf-8")
        return run_audit(path)

    @staticmethod
    def read_csv(path):
        with path.open(newline="", encoding="utf-8") as stream:
            reader = csv.DictReader(stream)
            return reader.fieldnames, list(reader)

    def test_feature_bridge_contains_only_retained_rows_and_allowlisted_columns(self):
        output = self.run_audit()
        _, splits = self.read_csv(output / "splits.csv")
        headers, features = self.read_csv(output / "retained_features.csv")
        self.assertEqual(headers, ["variant", "record_id", *self.config["feature_allowlist"]])
        expected = {(row["variant"], row["record_id"]) for row in splits if row["disposition"] == "retained"}
        observed = [(row["variant"], row["record_id"]) for row in features]
        self.assertEqual(set(observed), expected)
        self.assertEqual(len(observed), len(expected))
        rejected = {(row["variant"], row["record_id"]) for row in splits if row["disposition"] != "retained"}
        self.assertTrue(rejected)
        self.assertFalse(set(observed) & rejected)
        for row in features:
            self.assertTrue(all(math.isfinite(float(row[name])) for name in self.config["feature_allowlist"]))

    def test_bridge_values_join_to_source_records_by_audit_ids(self):
        output = self.run_audit()
        _, splits = self.read_csv(output / "splits.csv")
        _, feature_rows = self.read_csv(output / "retained_features.csv")
        features = {(row["variant"], row["record_id"]): row for row in feature_rows}
        source_rows = {}
        for dataset in self.config["datasets"]:
            for index, file in enumerate(dataset["files"]):
                _, rows = self.read_csv(Path(file))
                source_rows[dataset["variant"], index] = rows
        for audit in splits:
            if audit["disposition"] != "retained":
                continue
            source = source_rows[audit["variant"], int(audit["source_file_index"])][int(audit["source_record"]) - 2]
            feature = features[audit["variant"], audit["record_id"]]
            self.assertEqual(float(feature["flow_duration"]), float(source["Duration"]))
            self.assertEqual(float(feature["packet_count"]), float(source["Packets"]))

    def test_release_specific_time_and_category_label_adapters(self):
        dataset = self.config["datasets"][0]
        self.config["datasets"] = [dataset]
        dataset["files"] = ["release.csv"]
        dataset["timestamp_format"] = "%d/%m/%Y %H:%M:%S %z"
        dataset["timezone"] = "UTC"
        dataset["label_map_version"] = "release-specific-v2"
        dataset["label_map"] = {"Attempted exploit": {"binary": 1, "family": "attempted_exploit"}}
        dataset["columns"] = {
            "Start": "event_start", "Finish": "event_end", "Attempted Category": "source_label",
            "Effective Category": "effective_category", "Duration": "flow_duration", "Packets": "packet_count",
        }
        with (self.root / "release.csv").open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow(dataset["columns"])
            writer.writerow(["02/01/2026 05:30:00 +0530", "02/01/2026 05:30:01 +0530", "Attempted exploit", "No effect", 1000, 20])
        output = self.run_audit()
        _, rows = self.read_csv(output / "splits.csv")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event_start"], "2026-01-02T00:00:00+00:00")
        self.assertEqual(rows[0]["partition"], "validation")
        self.assertEqual(rows[0]["source_label"], "Attempted exploit")
        self.assertEqual(rows[0]["family"], "attempted_exploit")
        self.assertEqual(rows[0]["binary_label"], "1")
        headers, _ = self.read_csv(output / "retained_features.csv")
        self.assertNotIn("effective_category", headers)
        self.assertNotIn("source_label", headers)
        manifest = json.loads((output / "manifest.json").read_text())["datasets"][0]
        self.assertEqual(manifest["label_map_version"], "release-specific-v2")
        self.assertEqual(manifest["timestamp_format"], dataset["timestamp_format"])

    def test_json_and_safe_yaml_configs_have_same_contract(self):
        import yaml
        json_path = self.root / "config.json"
        yaml_path = self.root / "config.yaml"
        json_path.write_text(json.dumps(self.config), encoding="utf-8")
        yaml_path.write_text(yaml.safe_dump(self.config), encoding="utf-8")
        self.assertEqual(load_config(json_path), load_config(yaml_path))
        yaml_path.write_text("!!python/object/apply:builtins.str [unsafe]", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "YAML"):
            load_config(yaml_path)


if __name__ == "__main__":
    unittest.main()
