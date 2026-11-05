"""Paired configs must preserve shared controls and independent provenance."""

import copy
import json
from pathlib import Path
import tempfile
import unittest

from attack_traffic.paired import build_paired_config


class PairedConfigTests(unittest.TestCase):
    def setUp(self):
        repository = Path(__file__).resolve().parent.parent
        scratch = repository / ".test-tmp"
        scratch.mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.base = json.loads((repository / "configs/demo.json").read_text())
        self.base.update(temporal_basis="capture_date", profile="subset", boundaries={"validation_start": "2026-01-02", "test_start": "2026-01-03"}, training={"seed": 42, "n_estimators": 200}, label_map_version="fixture-v1")
        for index, variant in enumerate(("original", "corrected")):
            folder = self.root / variant
            folder.mkdir()
            config = copy.deepcopy(self.base)
            dataset = config["datasets"][index]
            dataset["files"] = ["flows.csv"]
            dataset["columns"].update(capture_date="capture_date", timing_status="timing_status")
            dataset["preparation"] = {"denominator": 100, "algorithm": "fixture-label-independent-v1"}
            config["datasets"] = [dataset]
            config["timezone"] = "unresolved" if variant == "original" else "UTC"
            (folder / "config.json").write_text(json.dumps(config))
            (folder / "flows.csv").write_text("fixture; builder must not parse or rebalance source flows\n")
        self.destination = self.root / "configs/paired.json"

    def build(self):
        return build_paired_config(self.root / "original", self.root / "corrected", self.destination, self.root / "run")

    def test_per_release_label_clock_and_paths_survive_build_without_touching_preparations(self):
        source = {path: path.read_bytes() for variant in ("original", "corrected") for path in (self.root / variant).iterdir()}
        result = json.loads(self.build().read_text())
        self.assertEqual(result["temporal_basis"], "capture_date")
        self.assertEqual([item["variant"] for item in result["datasets"]], ["original", "corrected"])
        self.assertEqual([item["timezone"] for item in result["datasets"]], ["unresolved", "UTC"])
        for item in result["datasets"]:
            self.assertTrue((self.destination.parent / item["files"][0]).is_file())
            self.assertTrue(item["label_map"])
        self.assertIn("not an untouched prospective holdout", " ".join(result["experiment_notes"]))
        self.assertEqual(source, {path: path.read_bytes() for path in source})

    def test_disagreed_units_models_boundaries_or_sampling_cannot_be_silently_compared(self):
        path = self.root / "corrected/config.json"
        original = json.loads(path.read_text())
        for key in ("feature_units", "training", "boundaries", "sampling", "algorithm"):
            with self.subTest(key=key):
                config = copy.deepcopy(original)
                if key == "feature_units":
                    config[key]["flow_duration"] = "milliseconds"
                elif key == "training":
                    config[key]["seed"] = 99
                elif key == "boundaries":
                    config[key]["test_start"] = "2026-01-04"
                elif key == "sampling":
                    config["datasets"][0]["preparation"]["denominator"] = 10
                else:
                    config["datasets"][0]["preparation"]["algorithm"] = "different-sampler"
                path.write_text(json.dumps(config))
                with self.assertRaises(ValueError):
                    self.build()
                self.assertFalse(self.destination.exists())

    def test_existing_paired_config_is_immutable(self):
        self.build()
        before = self.destination.read_bytes()
        with self.assertRaisesRegex(ValueError, "already exists"):
            self.build()
        self.assertEqual(before, self.destination.read_bytes())


if __name__ == "__main__":
    unittest.main()
