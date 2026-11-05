"""Capture-day chronology preserves uncertain local clocks as metadata."""

import copy
import csv
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from attack_traffic import run_audit
from attack_traffic.audit import TIME_FIELDS
from attack_traffic.report import rebuild_report
from attack_traffic.train import run_experiment


class CaptureDateTests(unittest.TestCase):
    def setUp(self):
        self.repo = Path(__file__).resolve().parent.parent
        scratch = self.repo / ".test-tmp"
        scratch.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = json.loads((self.repo / "configs/demo.json").read_text())
        self.config.update(output_dir="run", profile="synthetic", temporal_basis="capture_date", timezone="UTC")
        self.config["boundaries"] = {"validation_start": "2026-01-02", "test_start": "2026-01-03"}
        self.config["training"] = {"seed": 23, "n_estimators": 4, "max_depth": 3, "min_samples_leaf": 1, "n_jobs": 1, "max_rows_per_variant": 100, "fpr_target": .01, "alert_budget": 3}
        self.fields = ["event_start", "event_end", "source_label", *TIME_FIELDS, "flow_duration", "packet_count"]
        self.rows = {}
        for dataset in self.config["datasets"]:
            variant = dataset["variant"]
            dataset["files"] = [f"{variant}.csv"]
            dataset["columns"] = {field: field for field in self.fields}
            dataset["timezone"] = "unresolved" if variant == "original" else "UTC"
            self.rows[variant] = []
            for day in (1, 2, 3):
                for hour, attack in ((8, False), (9, True)):
                    row = {
                        "event_start": f"2026-01-0{day} {hour:02}:00:00" if variant == "corrected" else "",
                        "event_end": f"2026-01-0{day} {hour:02}:00:01" if variant == "corrected" else "",
                        "source_label": "ATTACK" if attack else "BENIGN",
                        "capture_date": f"2026-01-0{day}",
                        "source_timestamp": f"{day}/1/2026 {hour}:00",
                        "local_start_lower": f"2026-01-0{day}T{hour:02}:00:00" if variant == "original" else "",
                        "local_start_upper": f"2026-01-0{day}T{hour + 12:02}:00:59.999999" if variant == "original" else "",
                        "local_end_upper": f"2026-01-0{day}T{hour + 12:02}:01:01" if variant == "original" else "",
                        "origin_member": f"{variant}-day-{day}.csv", "origin_record": str(hour),
                        "timing_status": "ambiguous_12h_minute" if variant == "original" else "observed_utc",
                        "flow_duration": str(1000 + day * 100 + hour),
                        "packet_count": str((100 if attack else 0) + day * 2 + hour),
                    }
                    self.rows[variant].append(row)
        self.write_sources()

    def write_sources(self):
        for variant, rows in self.rows.items():
            self.write_csv(self.root / f"{variant}.csv", self.fields, rows)

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

    def config_path(self):
        path = self.root / "config.json"
        path.write_text(json.dumps(self.config), encoding="utf-8")
        return path

    def test_date_partitions_preserve_blank_utc_and_all_uncertainty_metadata(self):
        output = run_audit(self.config_path())
        _, splits = self.read_csv(output / "splits.csv")
        originals = [row for row in splits if row["variant"] == "original"]
        self.assertEqual([row["partition"] for row in originals], ["train", "train", "validation", "validation", "test", "test"])
        for row, source in zip(originals, self.rows["original"]):
            self.assertEqual(row["event_start"], "")
            self.assertEqual(row["event_end"], "")
            self.assertEqual(row["disposition"], "retained")
            self.assertEqual({field: row[field] for field in TIME_FIELDS}, {field: source[field] for field in TIME_FIELDS})
        inventory = json.loads((output / "inventory.json").read_text())["original"]
        self.assertIsNone(inventory["time_coverage"]["train"]["first_start"])
        self.assertEqual(inventory["time_coverage"]["train"]["first_capture_date"], "2026-01-01")

    def test_possible_local_end_crossing_is_quarantined(self):
        self.rows["original"][0]["local_end_upper"] = "2026-01-02T00:00:00"
        self.write_sources()
        output = run_audit(self.config_path())
        _, rows = self.read_csv(output / "splits.csv")
        first = next(row for row in rows if row["variant"] == "original")
        self.assertEqual(first["disposition"], "quarantined")
        self.assertEqual(first["reason"], "possibly_spans_partition_boundary")

    def test_unknown_end_bound_is_quarantined_but_bad_features_are_excluded(self):
        self.rows["original"][0]["local_end_upper"] = ""
        self.rows["original"][1]["local_end_upper"] = ""
        self.rows["original"][1]["flow_duration"] = "NaN"
        self.write_sources()
        output = run_audit(self.config_path())
        _, rows = self.read_csv(output / "splits.csv")
        originals = [row for row in rows if row["variant"] == "original"]
        self.assertEqual(originals[0]["disposition"], "quarantined")
        self.assertEqual(originals[0]["reason"], "unresolved_end_bound")
        self.assertEqual(originals[1]["disposition"], "excluded")
        self.assertIn("nonfinite_feature:flow_duration", originals[1]["reason"])

    def test_capture_date_or_interval_disagreement_fails_instead_of_inventing_time(self):
        original = copy.deepcopy(self.rows)
        cases = [
            ("corrected", "capture_date", "2026-01-04"),
            ("original", "local_start_lower", "2026-01-02T08:00:00"),
            ("original", "local_start_upper", "2026-01-01T07:00:00"),
            ("original", "local_start_lower", "2026-01-01T08:00:00+00:00"),
            ("original", "event_start", "2026-01-01 08:00:00"),
        ]
        for variant, field, value in cases:
            with self.subTest(variant=variant, field=field):
                self.rows = copy.deepcopy(original)
                self.rows[variant][0][field] = value
                self.write_sources()
                with self.assertRaises(ValueError):
                    run_audit(self.config_path())
                self.assertFalse((self.root / "run").exists())

    def test_negative_duration_is_excluded_and_source_order_duplicate_conflicts_are_counted(self):
        duplicate = copy.deepcopy(self.rows["original"][0])
        duplicate["source_label"] = "ATTACK"
        duplicate["origin_record"] = "999"
        self.rows["original"].insert(1, duplicate)
        self.rows["original"][-1]["flow_duration"] = "-1"
        self.write_sources()
        output = run_audit(self.config_path())
        quality = json.loads((output / "quality.json").read_text())["original"]
        self.assertEqual(quality["duplicate_conflicting_source_label_rows"], 1)
        self.assertEqual(quality["duplicate_conflicting_binary_label_rows"], 1)
        _, rows = self.read_csv(output / "splits.csv")
        originals = [row for row in rows if row["variant"] == "original"]
        self.assertEqual(originals[0]["disposition"], "retained")
        self.assertEqual(originals[1]["reason"], "later_duplicate")
        self.assertEqual(originals[-1]["reason"], "invalid_duration")

    def test_mixed_time_sources_round_trip_through_training_report_and_parquet(self):
        import pyarrow.parquet as pq
        run = run_experiment(self.config_path())
        before = {str(p.relative_to(run)): hashlib.sha256(p.read_bytes()).hexdigest() for p in run.rglob("*") if p.is_file()}
        report = rebuild_report(run, self.root / "report", charts=True, parquet=True)
        _, splits = self.read_csv(run / "audit/splits.csv")
        by_id = {row["record_id"]: row for row in splits}
        _, predictions = self.read_csv(run / "predictions.csv")
        for row in predictions:
            expected = by_id[row["record_id"]]
            self.assertEqual({field: row[field] for field in TIME_FIELDS}, {field: expected[field] for field in TIME_FIELDS})
            if row["variant"] == "original":
                self.assertEqual(row["event_start"], "")
        parquet_rows = pq.read_table(report / "predictions.parquet").to_pylist()
        self.assertEqual(len(parquet_rows), len(predictions))
        for row, expected in zip(parquet_rows, predictions):
            self.assertEqual({field: row[field] for field in TIME_FIELDS}, {field: expected[field] for field in TIME_FIELDS})
            self.assertEqual(row["event_start"], expected["event_start"])
        text = (report / "report.md").read_text()
        self.assertIn("capture-day partitions", text)
        self.assertIn("blank UTC event fields are intentional", text)
        self.assertNotIn("same feature policy, declared model settings and UTC time boundaries", text)
        self.assertEqual(before, {str(p.relative_to(run)): hashlib.sha256(p.read_bytes()).hexdigest() for p in run.rglob("*") if p.is_file()})

    def test_report_rejects_temporal_basis_mismatch(self):
        run = run_experiment(self.config_path())
        path = run / "manifest.json"
        manifest = json.loads(path.read_text())
        manifest["temporal_basis"] = "event_time"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaises(ValueError):
            rebuild_report(run, self.root / "report")
        self.assertFalse((self.root / "report").exists())

    def test_report_rejects_tampered_prediction_uncertainty_fields(self):
        run = run_experiment(self.config_path())
        path = run / "predictions.csv"
        headers, original = self.read_csv(path)
        for field, value in (("capture_date", "2026-01-01"), ("local_start_upper", "2026-01-02T01:00:00"), ("origin_record", "unknown")):
            with self.subTest(field=field):
                rows = copy.deepcopy(original)
                row = next(row for row in rows if row["variant"] == "original")
                row[field] = value
                self.write_csv(path, headers, rows)
                with self.assertRaises(ValueError):
                    rebuild_report(run, self.root / "report")
                self.assertFalse((self.root / "report").exists())


if __name__ == "__main__":
    unittest.main()
