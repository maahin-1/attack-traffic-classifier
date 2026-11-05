"""Optional report exports preserve evidence without training or inference."""

import csv
import importlib.util
from pathlib import Path
import tempfile
import unittest

from attack_traffic.exports import export_parquet, SPLIT_FIELDS, PREDICTION_FIELDS
from attack_traffic.plots import write_charts


class ExportTests(unittest.TestCase):
    def setUp(self):
        scratch = Path(__file__).resolve().parent.parent / ".test-tmp"
        scratch.mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source, self.output = self.root / "run", self.root / "report"
        (self.source / "audit").mkdir(parents=True)
        self.output.mkdir()

    @staticmethod
    def write(path, fields, rows):
        with path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    def inputs(self):
        split = dict.fromkeys(SPLIT_FIELDS, "")
        split.update(variant="corrected", record_id="000123", source_file_index="0", source_record="2", source_label="BENIGN", attempted_category="-1", binary_label="0", family="normal", partition="test", disposition="retained", event_start="2017-07-07T12:00:00+00:00")
        prediction = dict.fromkeys(PREDICTION_FIELDS, "")
        prediction.update(variant="corrected", model_id="constant-v1", model="baseline", record_id="000123", partition="test", source_label="BENIGN", family="normal", binary_label="0", attack_score="0.0", threshold="5e-324", prediction="0", event_start=split["event_start"])
        self.write(self.source / "audit/splits.csv", SPLIT_FIELDS, [split])
        self.write(self.source / "predictions.csv", PREDICTION_FIELDS, [prediction])
        return split, prediction

    @unittest.skipUnless(importlib.util.find_spec("pyarrow"), "PyArrow is an optional export dependency")
    def test_parquet_preserves_ids_raw_categories_empty_strings_and_subnormal_threshold(self):
        import pyarrow.parquet as pq

        split, prediction = self.inputs()
        before = {path: path.read_bytes() for path in self.source.rglob("*.csv")}
        self.assertEqual(export_parquet(self.source, self.output), ["splits.parquet", "predictions.parquet"])
        stored_split = pq.read_table(self.output / "splits.parquet").to_pylist()[0]
        stored_prediction = pq.read_table(self.output / "predictions.parquet").to_pylist()[0]
        for key in ("record_id", "attempted_category", "reason", "event_start"):
            self.assertEqual(stored_split[key], split[key])
        self.assertEqual(stored_split["binary_label"], 0)
        self.assertEqual(stored_prediction["threshold"], float(prediction["threshold"]))
        self.assertGreater(stored_prediction["threshold"], 0)
        self.assertEqual(stored_prediction["class_prediction"], "")
        self.assertEqual(before, {path: path.read_bytes() for path in before})

    @unittest.skipUnless(importlib.util.find_spec("pyarrow"), "PyArrow is an optional export dependency")
    def test_parquet_refuses_overwrite(self):
        self.inputs()
        path = self.output / "splits.parquet"
        path.write_bytes(b"existing")
        with self.assertRaisesRegex(ValueError, "already exists"):
            export_parquet(self.source, self.output)
        self.assertEqual(path.read_bytes(), b"existing")

    @unittest.skipUnless(importlib.util.find_spec("pyarrow"), "PyArrow is an optional export dependency")
    def test_parquet_rejects_missing_source_fields(self):
        self.inputs()
        self.write(self.source / "audit/splits.csv", ["record_id"], [{"record_id": "a"}])
        with self.assertRaisesRegex(ValueError, "schema"):
            export_parquet(self.source, self.output)
        self.assertFalse((self.output / "splits.parquet").exists())

    @unittest.skipUnless(importlib.util.find_spec("matplotlib"), "Matplotlib is an optional chart dependency")
    def test_charts_support_arbitrary_benign_family_names_and_unobserved_attacks(self):
        fields = ["variant", "model", "family", "training_support", "test_support", "seen_in_training", "binary_detection_recall", "family_attribution_recall"]
        common = dict(variant="corrected", model="random_forest", seen_in_training="False", family_attribution_recall="0")
        rows = [dict(common, family="normal", training_support="8", test_support="8", binary_detection_recall=""),
                dict(common, family="scan", training_support="0", test_support="2", binary_detection_recall="0"),
                dict(common, family="absent", training_support="0", test_support="0", binary_detection_recall="")]
        self.write(self.output / "per_class.csv", fields, rows)
        metric_fields = ["variant", "model", "partition", "tn", "fp", "fn", "tp"]
        self.write(self.output / "metrics.csv", metric_fields, [dict(variant="corrected", model="random_forest", partition="test", tn="8", fp="0", fn="2", tp="0")])
        files = write_charts(self.output)
        self.assertEqual(files, ["recall_by_family.png", "test_confusion.png"])
        for filename in files:
            self.assertTrue((self.output / filename).read_bytes().startswith(b"\x89PNG\r\n\x1a\n"))


if __name__ == "__main__":
    unittest.main()
