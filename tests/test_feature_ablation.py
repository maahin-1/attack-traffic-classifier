"""The 27/39 feature comparison keeps cohorts and fitting controls fixed."""

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
from sklearn.ensemble import RandomForestClassifier

from attack_traffic.evaluate import binary_metrics
from attack_traffic.feature_ablation import _select_candidate, run_feature_ablation
from attack_traffic.tune import run_weight_ablation
from test_feature_extract import extract_fixture, make_feature_source, read_csv, tree_hashes, write_csv


class FeatureAblationTests(unittest.TestCase):
    def setUp(self):
        scratch = Path(__file__).resolve().parent.parent / ".test-tmp"
        scratch.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fixture = make_feature_source(self.root / "fixture")
        self.source = self.fixture["source"]
        self.features = extract_fixture(self.fixture, self.root / "features")
        self.output = self.root / "ablation"

    def deny_test_results(self):
        forbidden = {(self.source / name).resolve() for name in ("metrics.json", "predictions.csv")}
        actual_open = Path.open
        def checked_open(path, *args, **kwargs):
            if path.resolve() in forbidden:
                raise AssertionError("Feature development must not read saved test results")
            return actual_open(path, *args, **kwargs)
        return patch.object(Path, "open", checked_open)

    def run_ablation(self):
        return run_feature_ablation(self.source, self.features, self.output)

    def refresh_feature_csv_digest(self):
        """Allow semantic-contract tests to get beyond accidental-damage checks."""
        path = self.features / "provenance.json"
        provenance = json.loads(path.read_text())
        provenance["extended_features_sha256"] = hashlib.sha256((self.features / "extended_features.csv").read_bytes()).hexdigest()
        path.write_text(json.dumps(provenance), encoding="utf-8")

    def test_candidates_use_same_ordered_cohorts_and_parameters_with_only_width_changed(self):
        before_source, before_features = tree_hashes(self.source), tree_hashes(self.features)
        fits = []
        actual_fit = RandomForestClassifier.fit
        def checked_fit(model, matrix, labels, *args, **kwargs):
            fits.append((model.get_params(), np.asarray(matrix).copy(), np.asarray(labels).copy()))
            self.assertEqual(model.class_weight, "balanced_subsample")
            self.assertEqual(len(matrix), 4)
            return actual_fit(model, matrix, labels, *args, **kwargs)
        with self.deny_test_results(), patch.object(RandomForestClassifier, "fit", checked_fit), patch("joblib.load") as load:
            output = self.run_ablation()
            load.assert_not_called()
        self.assertEqual(len(fits), 4)
        self.assertEqual(sorted(matrix.shape[1] for _, matrix, _ in fits), [27, 27, 39, 39])
        self.assertTrue(all(params == fits[0][0] for params, _, _ in fits))
        base = [item for item in fits if item[1].shape[1] == 27]
        expanded = [item for item in fits if item[1].shape[1] == 39]
        for baseline, candidate in zip(base, expanded):
            np.testing.assert_array_equal(baseline[1], candidate[1][:, :27])
            np.testing.assert_array_equal(baseline[2], candidate[2])
        self.assertEqual(tree_hashes(self.source), before_source)
        self.assertEqual(tree_hashes(self.features), before_features)
        for name in ("candidate_metrics.json", "candidate_metrics.csv", "validation_predictions.csv", "per_class_validation.csv", "selection.json", "report.md", "provenance.json"):
            self.assertTrue((output / name).is_file(), name)

    def test_baseline27_reproduces_previous_weight_ablation_reference(self):
        reference = run_weight_ablation(self.source, self.root / "weights")
        expected = json.loads((reference / "candidate_metrics.json").read_text())["candidates"]["balanced_subsample"]
        with self.deny_test_results():
            output = self.run_ablation()
        actual = json.loads((output / "candidate_metrics.json").read_text())["candidates"]["baseline27"]
        for variant in ("original", "corrected"):
            self.assertEqual(actual["variants"][variant]["validation"], expected["variants"][variant]["validation"])
            self.assertEqual(actual["variants"][variant]["threshold_policy"], expected["variants"][variant]["threshold_policy"])

    def test_saved_validation_predictions_reproduce_all_candidate_metrics(self):
        output = self.run_ablation()
        metrics = json.loads((output / "candidate_metrics.json").read_text())["candidates"]
        _, predictions = read_csv(output / "validation_predictions.csv")
        keys = [(row["candidate"], row["variant"], row["record_id"]) for row in predictions]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertTrue(all(row["partition"] == "validation" for row in predictions))
        for candidate, results in metrics.items():
            for variant, result in results["variants"].items():
                rows = [row for row in predictions if row["candidate"] == candidate and row["variant"] == variant]
                self.assertEqual(len(rows), 2)
                measured = binary_metrics([int(row["binary_label"]) for row in rows], [float(row["attack_score"]) for row in rows], result["threshold_policy"]["threshold"], [row["record_id"] for row in rows], 100)
                for field, value in measured.items():
                    self.assertEqual(result["validation"][field], value)

    def test_test_evidence_is_skipped_before_values_are_parsed(self):
        first = self.run_ablation()
        expected_metrics = json.loads((first / "candidate_metrics.json").read_text())
        expected_selection = json.loads((first / "selection.json").read_text())
        path = self.source / "audit/splits.csv"
        fields, rows = read_csv(path)
        test_ids = set()
        for row in rows:
            if row["partition"] == "test":
                test_ids.add(row["record_id"])
                row.update(source_label="unread-test-label", family="unread-test-family", binary_label="not-parsed", origin_member="not-a-member", origin_record="not-an-integer")
        write_csv(path, fields, rows)
        path = self.source / "audit/retained_features.csv"
        fields, rows = read_csv(path)
        for row in rows:
            if row["record_id"] in test_ids:
                row["flow_duration"] = "not-a-number"
        write_csv(path, fields, rows)
        for name in ("metrics.json", "predictions.csv"):
            (self.source / name).write_text("Never parse test results", encoding="utf-8")
        self.features = extract_fixture(self.fixture, self.root / "features-after-test-mutation")
        self.output = self.root / "ablation-after-test-mutation"
        with self.deny_test_results():
            second = self.run_ablation()
        self.assertEqual(json.loads((second / "candidate_metrics.json").read_text()), expected_metrics)
        self.assertEqual(json.loads((second / "selection.json").read_text()), expected_selection)

    def test_extraction_source_hash_mismatch_cannot_be_ignored(self):
        path = self.source / "audit/splits.csv"
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaises(ValueError):
            self.run_ablation()
        self.assertFalse(self.output.exists())

    def test_missing_duplicate_or_unknown_retained_extra_ids_fail_atomically(self):
        path = self.features / "extended_features.csv"
        original = path.read_bytes()
        fields, original_rows = read_csv(path)
        for case in ("missing", "duplicate", "unknown", "nonfinite"):
            with self.subTest(case=case):
                rows = copy.deepcopy(original_rows)
                index = next(i for i, row in enumerate(rows) if row["disposition"] == "retained")
                if case == "missing":
                    rows.pop(index)
                elif case == "duplicate":
                    rows.append(copy.deepcopy(rows[index]))
                elif case == "unknown":
                    rows[index]["record_id"] = "unknown-retained-id"
                else:
                    rows[index]["fwd_iat_mean"] = "NaN"
                write_csv(path, fields, rows)
                self.refresh_feature_csv_digest()
                with self.assertRaises(ValueError):
                    self.run_ablation()
                self.assertFalse(self.output.exists())
                path.write_bytes(original)

    def test_derived_values_and_cohort_order_are_verified_beyond_artifact_hash(self):
        path = self.features / "extended_features.csv"
        original = path.read_bytes()
        fields, original_rows = read_csv(path)
        for case in ("derived", "order"):
            with self.subTest(case=case):
                rows = copy.deepcopy(original_rows)
                retained = [i for i, row in enumerate(rows) if row["disposition"] == "retained" and row["variant"] == "original"]
                if case == "derived":
                    rows[retained[0]]["fwd_packet_fraction"] = "0.123456"
                else:
                    left, right = retained[:2]
                    rows[left], rows[right] = rows[right], rows[left]
                write_csv(path, fields, rows)
                self.refresh_feature_csv_digest()
                with self.assertRaises(ValueError):
                    self.run_ablation()
                self.assertFalse(self.output.exists())
                path.write_bytes(original)

    def test_test_only_extra_rows_are_skipped_before_ids_or_numbers_are_parsed(self):
        path = self.features / "extended_features.csv"
        fields, rows = read_csv(path)
        test_row = {field: "not-parsed" for field in fields}
        test_row.update(partition="test", disposition="retained")
        rows.append(test_row)
        write_csv(path, fields, rows)
        self.refresh_feature_csv_digest()
        output = self.run_ablation()
        metrics = json.loads((output / "candidate_metrics.json").read_text())["candidates"]
        self.assertTrue(all(result["status"] == "ok" for candidate in metrics.values() for result in candidate["variants"].values()))

    def test_invalid_diagnostic_rows_do_not_enter_or_change_candidate_cohorts(self):
        fixture = make_feature_source(self.root / "invalid-diagnostic", invalid_extra="diagnostic")
        features = extract_fixture(fixture, self.root / "diagnostic-features")
        output = run_feature_ablation(fixture["source"], features, self.output)
        metrics = json.loads((output / "candidate_metrics.json").read_text())["candidates"]
        self.assertTrue(all(result["status"] == "ok" for candidate in metrics.values() for result in candidate["variants"].values()))

    def test_extra_definition_and_archive_identity_mismatches_are_rejected(self):
        path = self.features / "provenance.json"
        original = path.read_bytes()
        for case in ("unit", "archive"):
            with self.subTest(case=case):
                provenance = json.loads(original)
                if case == "unit":
                    provenance["feature_definitions"]["fwd_iat_mean"]["unit"] = "milliseconds"
                else:
                    provenance["archives"]["original"]["archive_sha256"] = "0" * 64
                path.write_text(json.dumps(provenance), encoding="utf-8")
                with self.assertRaises(ValueError):
                    self.run_ablation()
                self.assertFalse(self.output.exists())

    def test_rehashed_negative_iat_and_out_of_range_fraction_block_all_fits(self):
        path = self.features / "extended_features.csv"
        fields, original_rows = read_csv(path)
        for feature, value in (("fwd_iat_mean", "-1"), ("fwd_packet_fraction", "1.1")):
            with self.subTest(feature=feature):
                rows = copy.deepcopy(original_rows)
                row = next(row for row in rows if row["disposition"] == "retained")
                row[feature] = value
                write_csv(path, fields, rows)
                self.refresh_feature_csv_digest()
                with patch.object(RandomForestClassifier, "fit") as fit:
                    with self.assertRaises(ValueError):
                        self.run_ablation()
                    fit.assert_not_called()
                self.assertFalse(self.output.exists())

    def test_invalid_extraction_status_is_not_silently_fixed_by_dropping_rows(self):
        fixture = make_feature_source(self.root / "invalid-fixture", invalid_extra="retained")
        features = extract_fixture(fixture, self.root / "invalid-features")
        with self.assertRaises(ValueError):
            run_feature_ablation(fixture["source"], features, self.output)
        self.assertFalse(self.output.exists())

    def test_existing_output_is_immutable(self):
        output = self.run_ablation()
        before = tree_hashes(output)
        with self.assertRaises(ValueError):
            self.run_ablation()
        self.assertEqual(tree_hashes(output), before)


class FeatureSelectionTests(unittest.TestCase):
    @staticmethod
    def candidates(base, expanded):
        return {name: {"variants": {variant: {"status": "ok", "validation": {"recall": recall, "fpr": fpr}, "threshold_policy": {"fpr_target": .01}} for variant, (recall, fpr) in zip(("original", "corrected"), values)}} for name, values in (("baseline27", base), ("expanded39", expanded))}

    def test_joint_fpr_limit_and_variant_nonregression_are_required(self):
        for expanded in ([(.8, .02), (.8, 0)], [(.8, .005), (.1, .005)]):
            with self.subTest(expanded=expanded):
                result = _select_candidate(self.candidates([(.2, .005), (.2, .005)], expanded))
                self.assertFalse(result["promotion_passed"])
                self.assertEqual(result["promoted_candidate"], "baseline27")

    def test_subtolerance_change_and_missing_variant_cannot_promote(self):
        candidates = self.candidates([(.2, .005), (.2, .005)], [(.2 + 5e-13, .005), (.2 + 5e-13, .005)])
        self.assertFalse(_select_candidate(candidates)["promotion_passed"])
        candidates = self.candidates([(.2, .005), (.2, .005)], [(.9, .005), (.9, .005)])
        del candidates["expanded39"]["variants"]["corrected"]
        result = _select_candidate(candidates)
        self.assertFalse(candidates["expanded39"]["eligible"])
        self.assertEqual(result["promoted_candidate"], "baseline27")


if __name__ == "__main__":
    unittest.main()
