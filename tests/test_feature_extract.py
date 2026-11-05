"""Raw IAT extraction follows frozen source ordinals, never test captures."""

import copy
import csv
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from attack_traffic.feature_extract import EXTRA_FEATURES, RAW_EXTRA_FEATURES, extract_features
from attack_traffic.original import ORIGINAL_MEMBERS, prepare_original_subset
from attack_traffic.paired import build_paired_config
from attack_traffic.prepare import DAYS, FEATURES, prepare_subset
from attack_traffic.train import run_experiment
from test_original import PUBLISHER_HEADERS


def read_csv(path):
    with path.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        return reader.fieldnames, list(reader)


def write_csv(path, fields, rows):
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def tree_hashes(directory):
    return {str(path.relative_to(directory)): hashlib.sha256(path.read_bytes()).hexdigest() for path in directory.rglob("*") if path.is_file()}


def make_feature_source(root, invalid_extra=None):
    """Create both publisher layouts and a tiny immutable 27-feature source run."""
    root.mkdir(parents=True, exist_ok=True)
    original, corrected = root / "original.zip", root / "corrected.zip"
    raw_names = ["Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min"]
    day_number = {"monday": 3, "tuesday": 4, "wednesday": 5, "thursday": 6, "friday": 7}
    with zipfile.ZipFile(original, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("TrafficLabelling /", "")
        for index, member in enumerate(sorted(ORIGINAL_MEMBERS)):
            day_name = member.split("/")[-1].split("-")[0].lower()
            day = day_number[day_name]
            rows = []
            for hour, attack in ((8, False), (9, True)):
                zero = day_name == "monday" and not attack
                label = "Web Attack – Brute Force" if day_name == "wednesday" and attack else "FTP-Patator" if attack else "BENIGN"
                row = []
                for header in PUBLISHER_HEADERS:
                    name = header.strip()
                    value = "0" if zero else str(index * 100 + hour)
                    if name in raw_names:
                        value = "0" if zero else str(index * 10 + hour)
                    if name == "Timestamp":
                        value = f"{day}/7/2017 {hour}:00"
                    elif name == "Label":
                        value = label
                    elif name in ("Flow ID", "Source IP", "Destination IP"):
                        value = "private-endpoint-sentinel"
                    row.append(value)
                rows.append(row)
            if day_name == "monday":
                duplicate = rows[0][:]
                for position, header in enumerate(PUBLISHER_HEADERS):
                    if header.strip() in raw_names:
                        duplicate[position] = "9"
                    elif header.strip() == "Label":
                        duplicate[position] = "FTP-Patator"
                    elif header.strip() == "Timestamp":
                        duplicate[position] = f"{day}/7/2017 10:00"
                rows.append(duplicate)
                if invalid_extra:
                    target = 2 if invalid_extra == "diagnostic" else 0
                    position = next(i for i, header in enumerate(PUBLISHER_HEADERS) if header.strip() == "Fwd IAT Mean")
                    rows[target][position] = "-1" if invalid_extra == "negative" else "NaN"
            text = io.StringIO(newline="")
            writer = csv.writer(text)
            writer.writerow(PUBLISHER_HEADERS)
            writer.writerows(rows)
            bundle.writestr(member, text.getvalue().encode("cp1252"))
    with zipfile.ZipFile(corrected, "w", zipfile.ZIP_DEFLATED) as bundle:
        headers = ["Timestamp", "Label", "Attempted Category", *FEATURES, *raw_names]
        for index, member in enumerate(sorted(DAYS)):
            day_name = member[:-4]
            day = day_number[day_name]
            rows = []
            for hour, attack in ((8, False), (9, True)):
                zero = day_name == "monday" and not attack
                row = {field: "0" if zero else str(index * 100 + hour) for field in FEATURES}
                row.update({field: "0" if zero else str(index * 10 + hour) for field in raw_names})
                row.update(Timestamp=f"2017-07-{day:02d} {hour:02}:00:00.000000", Label="Web Attack - Brute Force" if day_name == "wednesday" and attack else "FTP-Patator" if attack else "BENIGN")
                row["Attempted Category"] = row["Label"]
                rows.append(row)
            if day_name == "monday":
                duplicate = dict(rows[0], Label="FTP-Patator", Timestamp=f"2017-07-{day:02d} 10:00:00.000000")
                duplicate.update({field: "9" for field in raw_names})
                rows.append(duplicate)
            text = io.StringIO(newline="")
            writer = csv.DictWriter(text, fieldnames=headers)
            writer.writeheader()
            writer.writerows(rows)
            bundle.writestr(member, text.getvalue())
    acquisitions = []
    for variant, archive in (("original", original), ("corrected", corrected)):
        path = root / f"{variant}-acquisition.json"
        path.write_text(json.dumps({"variant": variant, "source_url": f"synthetic://{variant}", "retrieved_at": "2026-11-02T00:00:00Z", "license_status": "Synthetic fixture", "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}), encoding="utf-8")
        acquisitions.append(path)
    original_dir = prepare_original_subset(original, acquisitions[0], root / "original-prepared", 1, 100)
    corrected_dir = prepare_subset(corrected, acquisitions[1], root / "corrected-prepared", 1, 100, temporal_basis="capture_date")
    config_path = build_paired_config(original_dir, corrected_dir, root / "paired.json", root / "source")
    config = json.loads(config_path.read_text())
    config["training"].update(n_estimators=4, max_depth=3, min_samples_leaf=1, max_rows_per_variant=100)
    config_path.write_text(json.dumps(config), encoding="utf-8")
    source = run_experiment(config_path)
    return {"source": source, "original": original, "corrected": corrected, "original_acquisition": acquisitions[0], "corrected_acquisition": acquisitions[1]}


def extract_fixture(fixture, output):
    return extract_features(fixture["source"], fixture["original"], fixture["original_acquisition"], fixture["corrected"], fixture["corrected_acquisition"], output)


class FeatureExtractionTests(unittest.TestCase):
    def setUp(self):
        scratch = Path(__file__).resolve().parent.parent / ".test-tmp"
        scratch.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fixture = make_feature_source(self.root / "fixture")
        self.output = self.root / "extracted"

    def test_extraction_reads_only_train_validation_members_and_preserves_sources(self):
        before = tree_hashes(self.fixture["source"])
        original_open = zipfile.ZipFile.open
        opened = []
        def checked_open(bundle, member, *args, **kwargs):
            name = member.filename if hasattr(member, "filename") else str(member)
            self.assertNotIn("thursday", name.lower())
            self.assertNotIn("friday", name.lower())
            opened.append(name)
            return original_open(bundle, member, *args, **kwargs)
        with patch.object(zipfile.ZipFile, "open", checked_open), patch("joblib.load") as load, patch("sklearn.ensemble.RandomForestClassifier.fit") as fit:
            output = extract_fixture(self.fixture, self.output)
            load.assert_not_called()
            fit.assert_not_called()
        self.assertTrue(opened)
        self.assertEqual(tree_hashes(self.fixture["source"]), before)
        summary = json.loads((output / "summary.json").read_text())
        self.assertEqual(summary["status"], "ok")
        headers, rows = read_csv(output / "extended_features.csv")
        self.assertEqual(set(headers), {"variant", "record_id", "partition", "disposition", "duplicate_group_id", *EXTRA_FEATURES})
        self.assertTrue(all(row["partition"] in {"train", "validation"} for row in rows))
        _, splits = read_csv(self.fixture["source"] / "audit/splits.csv")
        expected = {(row["variant"], row["record_id"]) for row in splits if row["partition"] in {"train", "validation"} and (row["disposition"] == "retained" or row["reason"] == "later_duplicate")}
        self.assertEqual({(row["variant"], row["record_id"]) for row in rows}, expected)
        self.assertEqual(len(EXTRA_FEATURES), 12)
        self.assertEqual(len(RAW_EXTRA_FEATURES), 8)

    def test_zero_denominator_ratios_are_zero_and_only_raw8_refine_base_ties(self):
        output = extract_fixture(self.fixture, self.output)
        _, rows = read_csv(output / "extended_features.csv")
        summary = json.loads((output / "summary.json").read_text())
        derived = ["fwd_packet_fraction", "fwd_byte_fraction", "fwd_bytes_per_packet", "bwd_bytes_per_packet"]
        for variant in ("original", "corrected"):
            duplicate = next(row for row in rows if row["variant"] == variant and row["disposition"] == "quarantined")
            retained = next(row for row in rows if row["variant"] == variant and row["duplicate_group_id"] == duplicate["duplicate_group_id"] and row["disposition"] == "retained")
            self.assertTrue(all(float(retained[name]) == 0 and float(duplicate[name]) == 0 for name in derived))
            self.assertTrue(any(retained[name] != duplicate[name] for name in EXTRA_FEATURES if name not in derived))
            evidence = summary["variants"][variant]
            self.assertEqual(evidence["derived4_splits_exact_base_groups"], 0)
            self.assertGreater(evidence["after_raw8"]["feature_group_count"], evidence["before"]["feature_group_count"])
            self.assertLess(evidence["after_raw8"]["binary_conflict_group_count"], evidence["before"]["binary_conflict_group_count"])
            ordinary = next(row for row in rows if row["variant"] == variant and float(row["fwd_packet_fraction"]) != 0)
            self.assertEqual(float(ordinary["fwd_packet_fraction"]), .5)
            self.assertEqual(float(ordinary["fwd_byte_fraction"]), .5)
            self.assertEqual(float(ordinary["fwd_bytes_per_packet"]), 1)
            self.assertEqual(float(ordinary["bwd_bytes_per_packet"]), 1)

    def test_invalid_retained_raw_extra_is_reported_without_dropping_row(self):
        fixture = make_feature_source(self.root / "invalid-fixture", invalid_extra="retained")
        output = extract_fixture(fixture, self.output)
        summary = json.loads((output / "summary.json").read_text())
        self.assertEqual(summary["status"], "failed_extra_validation")
        self.assertEqual(summary["invalid_retained_rows"], 1)
        self.assertTrue((output / "invalid_features.csv").is_file())
        _, rows = read_csv(output / "extended_features.csv")
        _, splits = read_csv(fixture["source"] / "audit/splits.csv")
        expected = [row for row in splits if row["partition"] in {"train", "validation"} and (row["disposition"] == "retained" or row["reason"] == "later_duplicate")]
        self.assertEqual(len(rows), len(expected))

    def test_invalid_diagnostic_extra_does_not_create_optimistic_collision_result(self):
        fixture = make_feature_source(self.root / "invalid-diagnostic", invalid_extra="diagnostic")
        output = extract_fixture(fixture, self.output)
        summary = json.loads((output / "summary.json").read_text())
        self.assertEqual(summary["status"], "ok")
        self.assertEqual(summary["invalid_diagnostic_rows"], 1)
        self.assertIsNone(summary["variants"]["original"]["after_raw8"])

    def test_archive_acquisition_hash_mismatch_fails_atomically(self):
        path = self.fixture["original_acquisition"]
        metadata = json.loads(path.read_text())
        metadata["sha256"] = "0" * 64
        path.write_text(json.dumps(metadata), encoding="utf-8")
        with self.assertRaises(ValueError):
            extract_fixture(self.fixture, self.output)
        self.assertFalse(self.output.exists())

    def test_wrong_raw_reference_label_or_frozen27_hash_is_rejected(self):
        path = self.fixture["source"] / "audit/splits.csv"
        original = path.read_bytes()
        fields, original_rows = read_csv(path)
        for case in ("origin_record", "origin_member", "label", "hash"):
            with self.subTest(case=case):
                rows = copy.deepcopy(original_rows)
                row = next(row for row in rows if row["variant"] == "original" and row["partition"] == "train" and row["disposition"] == "retained")
                if case == "origin_record":
                    row["origin_record"] = "9999"
                elif case == "origin_member":
                    row["origin_member"] = "../unknown.csv"
                elif case == "label":
                    row.update(source_label="FTP-Patator", family="FTP-Patator", binary_label="1")
                else:
                    row["duplicate_group_id"] = "0" * 64
                write_csv(path, fields, rows)
                with self.assertRaises(ValueError):
                    extract_fixture(self.fixture, self.output)
                self.assertFalse(self.output.exists())
                path.write_bytes(original)

    def test_existing_extraction_output_is_immutable(self):
        output = extract_fixture(self.fixture, self.output)
        before = tree_hashes(output)
        with self.assertRaises(ValueError):
            extract_fixture(self.fixture, self.output)
        self.assertEqual(tree_hashes(output), before)

    def test_test_labels_origin_references_and_base_values_are_never_interpreted(self):
        first = extract_fixture(self.fixture, self.output)
        expected = (first / "extended_features.csv").read_bytes()
        path = self.fixture["source"] / "audit/splits.csv"
        fields, rows = read_csv(path)
        test_ids = set()
        for row in rows:
            if row["partition"] == "test":
                test_ids.add(row["record_id"])
                row.update(source_label="not-a-known-label", binary_label="not-an-integer", origin_member="../unread-test.csv", origin_record="not-an-ordinal")
        write_csv(path, fields, rows)
        path = self.fixture["source"] / "audit/retained_features.csv"
        fields, rows = read_csv(path)
        for row in rows:
            if row["record_id"] in test_ids:
                row["flow_duration"] = "not-a-number"
        write_csv(path, fields, rows)
        second = extract_fixture(self.fixture, self.root / "after-test-mutation")
        self.assertEqual((second / "extended_features.csv").read_bytes(), expected)

    def test_frozen_raw_base_values_and_timestamp_metadata_cannot_be_forged(self):
        source = self.fixture["source"]
        path = source / "audit/retained_features.csv"
        fields, rows = read_csv(path)
        original = path.read_bytes()
        rows[0]["flow_duration"] = "999999"
        write_csv(path, fields, rows)
        with self.assertRaises(ValueError):
            extract_fixture(self.fixture, self.output)
        self.assertFalse(self.output.exists())
        path.write_bytes(original)
        path = source / "audit/splits.csv"
        fields, rows = read_csv(path)
        selected = next(row for row in rows if row["partition"] == "train" and row["disposition"] == "retained")
        selected["source_timestamp"] = "forged-source-clock"
        write_csv(path, fields, rows)
        with self.assertRaises(ValueError):
            extract_fixture(self.fixture, self.output)
        self.assertFalse(self.output.exists())

    def test_negative_raw_iat_statistic_blocks_retained_row_validation(self):
        fixture = make_feature_source(self.root / "negative-fixture", invalid_extra="negative")
        output = extract_fixture(fixture, self.output)
        summary = json.loads((output / "summary.json").read_text())
        self.assertEqual(summary["status"], "failed_extra_validation")
        self.assertEqual(summary["invalid_retained_rows"], 1)

    def test_frozen_archive_identity_and_config_hash_are_independently_checked(self):
        source = self.fixture["source"]
        config_path, manifest_path = source / "config.json", source / "manifest.json"
        original_config, original_manifest = config_path.read_bytes(), manifest_path.read_bytes()
        config = json.loads(original_config)
        config["experiment_notes"].append("unhashed config edit")
        config_path.write_text(json.dumps(config), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "(?i)config hash"):
            extract_fixture(self.fixture, self.output)
        config = json.loads(original_config)
        config["datasets"][0]["preparation"]["archive_sha256"] = "0" * 64
        manifest = json.loads(original_manifest)
        manifest["config_sha256"] = hashlib.sha256(json.dumps(config, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        config_path.write_text(json.dumps(config), encoding="utf-8")
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "(?i)(archive|preparation)"):
            extract_fixture(self.fixture, self.output)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
