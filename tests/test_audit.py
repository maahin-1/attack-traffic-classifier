"""Data-contract and leakage regressions; all data are generated locally."""

import csv
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from attack_traffic import run_audit


class AuditTests(unittest.TestCase):
    def setUp(self):
        scratch = Path(__file__).resolve().parent.parent / ".test-tmp"
        scratch.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.columns = ["Timestamp", "End", "Label", "Duration", "Packets", "Source IP"]
        self.config = {
            "version": 1,
            "output_dir": "output",
            "feature_allowlist": ["flow_duration", "packet_count"],
            "feature_units": {"flow_duration": "microseconds", "packet_count": "count"},
            "label_map_version": "test-v1",
            "label_map": {
                "BENIGN": {"binary": 0, "family": "benign"},
                "ATTACK": {"binary": 1, "family": "attack"},
            },
            "timestamp_format": "%Y-%m-%d %H:%M:%S",
            "timezone": "UTC",
            "boundaries": {
                "validation_start": "2026-01-02T00:00:00+00:00",
                "test_start": "2026-01-03T00:00:00+00:00",
            },
            "datasets": [{
                "variant": "original", "release": "synthetic-v1",
                "source_url": "synthetic://unit-test",
                "retrieved_at": "2026-11-02T00:00:00Z",
                "license": "CC0 synthetic fixture", "files": ["flows.csv"],
                "columns": {
                    "Timestamp": "event_start", "End": "event_end", "Label": "source_label",
                    "Duration": "flow_duration", "Packets": "packet_count", "Source IP": "source_ip",
                },
            }],
        }

    @staticmethod
    def row(day=1, duration=10, packets=1, label="BENIGN", start="12:00:00", end="12:00:01"):
        return [f"2026-01-0{day} {start}", f"2026-01-0{day} {end}", label, duration, packets, "192.0.2.1"]

    def write_rows(self, rows, name="flows.csv", columns=None):
        with (self.root / name).open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow(columns or self.columns)
            writer.writerows(rows)

    def run_config(self):
        path = self.root / "config.json"
        path.write_text(json.dumps(self.config), encoding="utf-8")
        return run_audit(path)

    @staticmethod
    def splits(output):
        with (output / "splits.csv").open(newline="", encoding="utf-8") as stream:
            return list(csv.DictReader(stream))

    def test_valid_run_has_artifacts_and_correct_file_hash(self):
        self.write_rows([self.row(1, 10), self.row(2, 20, label="ATTACK"), self.row(3, 30)])
        output = self.run_config()
        for name in ("manifest.json", "quality.json", "splits.csv", "feature_list.json", "inventory.json", "config.json", "report.md"):
            self.assertTrue((output / name).is_file(), name)
        manifest_text = (output / "manifest.json").read_text(encoding="utf-8")
        expected_hash = hashlib.sha256((self.root / "flows.csv").read_bytes()).hexdigest()
        self.assertIn(expected_hash, manifest_text)
        rows = self.splits(output)
        self.assertEqual(len(rows), 3)
        self.assertEqual([row["partition"] for row in rows], ["train", "validation", "test"])

    def test_identifier_allowlist_fails_closed(self):
        self.write_rows([self.row()])
        for feature in ("source_ip", "destination_port", "source_label", "timestamp", "flow_id", "row_index"):
            with self.subTest(feature=feature):
                self.config["feature_allowlist"] = [feature]
                self.config["feature_units"][feature] = "sentinel"
                with self.assertRaises(ValueError):
                    self.run_config()

    def test_unknown_label_fails_instead_of_becoming_attack(self):
        self.write_rows([self.row(label="UNMAPPED")])
        with self.assertRaisesRegex(ValueError, "(?i)label"):
            self.run_config()

    def test_missing_mapped_column_fails(self):
        self.write_rows([self.row()[:-1]], columns=self.columns[:-1])
        with self.assertRaises(ValueError):
            self.run_config()

    def test_unexpected_column_fails(self):
        self.write_rows([self.row() + ["unmapped"]], columns=self.columns + ["Surprise"])
        with self.assertRaises(ValueError):
            self.run_config()

    def test_output_is_immutable(self):
        self.write_rows([self.row()])
        output = self.run_config()
        before = {p.name: p.read_bytes() for p in output.iterdir() if p.is_file()}
        with self.assertRaises((ValueError, FileExistsError)):
            self.run_config()
        self.assertEqual(before, {p.name: p.read_bytes() for p in output.iterdir() if p.is_file()})

    def test_out_of_order_file_is_rejected(self):
        self.write_rows([self.row(2, 20), self.row(1, 10)])
        with self.assertRaisesRegex(ValueError, "(?i)(sort|order|chronolog)"):
            self.run_config()

    def test_quality_accounting_and_class_counts_include_bad_rows(self):
        rows = [self.row(1, 10)]
        for number, value in enumerate(("NaN", "inf", "not-a-number", -1), start=1):
            rows.append(self.row(2, value, packets=number, label="ATTACK"))
        self.write_rows(rows)
        output = self.run_config()
        splits = self.splits(output)
        self.assertEqual(len(splits), 5)
        self.assertEqual([r["disposition"] for r in splits], ["retained"] + ["excluded"] * 4)
        quality = json.loads((output / "quality.json").read_text())["original"]
        self.assertEqual(quality["input_rows"], 5)
        self.assertEqual(quality["dispositions"], {"retained": 1, "excluded": 4, "quarantined": 0})
        self.assertEqual(sum(quality["dispositions"].values()), quality["input_rows"])
        self.assertIn("ATTACK", quality["by_source_label"])
        self.assertEqual(len({r["record_id"] for r in splits}), 5)

    def test_later_duplicate_cannot_cross_partitions(self):
        self.write_rows([self.row(1, 10), self.row(2, 10, label="ATTACK"), self.row(3, 30)])
        splits = self.splits(self.run_config())
        self.assertEqual(splits[0]["disposition"], "retained")
        self.assertEqual(splits[1]["disposition"], "quarantined")
        self.assertEqual(splits[1]["reason"], "later_duplicate")
        self.assertEqual(splits[0]["duplicate_group_id"], splits[1]["duplicate_group_id"])
        self.assertEqual(splits[2]["disposition"], "retained")

    def test_boundary_spanning_flow_is_quarantined(self):
        spanning = self.row(1, 10, start="23:59:59")
        spanning[1] = "2026-01-02 00:00:01"
        self.write_rows([spanning, self.row(2, 20)])
        splits = self.splits(self.run_config())
        self.assertEqual(splits[0]["partition"], "train")
        self.assertEqual(splits[0]["disposition"], "quarantined")
        self.assertEqual(splits[0]["reason"], "spans_partition_boundary")
        self.assertEqual(splits[1]["disposition"], "retained")

    def test_multiple_files_are_merged_before_deduplication(self):
        self.write_rows([self.row(3, 10)], name="later.csv")
        self.write_rows([self.row(1, 10)], name="earlier.csv")
        self.config["datasets"][0]["files"] = ["later.csv", "earlier.csv"]
        splits = self.splits(self.run_config())
        self.assertEqual([r["partition"] for r in splits], ["train", "test"])
        self.assertEqual([r["disposition"] for r in splits], ["retained", "quarantined"])

    def test_failure_does_not_publish_partial_output(self):
        self.write_rows([self.row(1, 10), self.row(2, 20, label="UNMAPPED")])
        with self.assertRaises(ValueError):
            self.run_config()
        self.assertFalse((self.root / "output").exists())
        self.assertFalse(list(self.root.glob(".audit-*")))

    def test_malformed_nested_config_returns_actionable_validation_error(self):
        self.write_rows([self.row()])
        original = copy.deepcopy(self.config)
        for field, value in (("boundaries", None), ("datasets", [None]), ("feature_units", None)):
            with self.subTest(field=field):
                self.config = copy.deepcopy(original)
                self.config[field] = value
                with self.assertRaises(ValueError):
                    self.run_config()

    def test_label_derived_category_fields_cannot_be_model_features(self):
        original = copy.deepcopy(self.config)
        for feature in ("attempted_category", "effective_category", "category"):
            with self.subTest(feature=feature):
                self.config = copy.deepcopy(original)
                self.config["feature_allowlist"] = [feature]
                self.config["feature_units"] = {feature: "count"}
                self.config["datasets"][0]["columns"]["Packets"] = feature
                self.write_rows([self.row()])
                with self.assertRaises(ValueError):
                    self.run_config()
        self.config = copy.deepcopy(original)
        self.config["datasets"][0]["columns"].pop("Packets")
        self.config["datasets"][0]["columns"]["Attempted Category"] = "packet_count"
        columns = ["Attempted Category" if c == "Packets" else c for c in self.columns]
        self.write_rows([self.row()], columns=columns)
        with self.assertRaises(ValueError):
            self.run_config()

    def test_distinct_identical_files_have_unique_record_ids(self):
        rows = [self.row()]
        self.write_rows(rows, name="first.csv")
        self.write_rows(rows, name="second.csv")
        self.assertEqual((self.root / "first.csv").read_bytes(), (self.root / "second.csv").read_bytes())
        self.config["datasets"][0]["files"] = ["first.csv", "second.csv"]
        splits = self.splits(self.run_config())
        self.assertEqual(len(splits), 2)
        self.assertEqual(len({row["record_id"] for row in splits}), 2)
        self.assertEqual([row["disposition"] for row in splits], ["retained", "quarantined"])


if __name__ == "__main__":
    unittest.main()
