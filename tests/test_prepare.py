"""Offline ZIP-adapter regressions using project-authored fake traffic."""

import csv
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from attack_traffic import run_audit
from attack_traffic.prepare import DAYS, FEATURES, TIME_FORMAT, prepare_subset, selected_record


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.repo = Path(__file__).resolve().parent.parent
        scratch = self.repo / ".test-tmp"
        scratch.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = self.root / "corrected.zip"
        self.acquisition = self.root / "acquisition.json"
        self.output = self.root / "prepared"
        self.headers = ["Timestamp", "Label", "Attempted Category", *FEATURES, "Src IP", "Dst IP", "Src Port", "Dst Port", "Flow ID"]
        dates = {"monday.csv": 3, "tuesday.csv": 4, "wednesday.csv": 5, "thursday.csv": 6, "friday.csv": 7}
        self.members = {}
        labels = ["BENIGN", "Exploit - Attempted", "Exploit", "Exploit - attempted", "Exploit - Attempted extra"]
        for index, (name, day) in enumerate(dates.items()):
            rows = []
            for hour in (10, 8):  # Deliberately unsorted within every daily file.
                row = {feature: str(index * 100 + hour) for feature in FEATURES}
                row.update({
                    "Timestamp": f"2017-07-{day:02d} {hour:02d}:00:00.000000",
                    "Label": labels[index], "Attempted Category": f"raw-attempt-{index}-{hour}",
                    "Flow Duration": "1234567", "Src IP": "192.0.2.123", "Dst IP": "198.51.100.45",
                    "Src Port": "45678", "Dst Port": "443", "Flow ID": "sensitive-endpoint-sentinel",
                })
                rows.append(row)
            self.members[name] = rows
        self.write_archive()

    def write_archive(self, member_names=None):
        with zipfile.ZipFile(self.archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            for name in member_names or self.members:
                content = io.StringIO(newline="")
                writer = csv.DictWriter(content, fieldnames=self.headers)
                writer.writeheader()
                writer.writerows(self.members.get(name, []))
                bundle.writestr(name, content.getvalue())
        provenance = {
            "sha256": hashlib.sha256(self.archive.read_bytes()).hexdigest(),
            "source_url": "synthetic://corrected-test-archive",
            "retrieved_at": "2026-11-02T00:00:00Z",
            "license_status": "Project-authored synthetic fixture",
        }
        self.acquisition.write_text(json.dumps(provenance), encoding="utf-8")

    @staticmethod
    def read_csv(path):
        with path.open(newline="", encoding="utf-8") as stream:
            reader = csv.DictReader(stream)
            return reader.fieldnames, list(reader)

    def prepare(self, denominator=1, max_rows=20):
        return prepare_subset(self.archive, self.acquisition, self.output, denominator, max_rows)

    def assert_no_published_or_staged_output(self):
        self.assertFalse(self.output.exists())
        self.assertFalse(list(self.root.glob(".prepare-*")))

    def test_unsorted_daily_records_become_one_sorted_feature_only_subset(self):
        output = self.prepare()
        headers, rows = self.read_csv(output / "flows.csv")
        self.assertEqual(len(rows), 10)
        starts = [row["event_start"] for row in rows]
        self.assertEqual(starts, sorted(starts))
        self.assertEqual(rows[0]["event_start"], "2017-07-03 08:00:00.000000")
        self.assertEqual(rows[-1]["event_start"], "2017-07-07 10:00:00.000000")
        self.assertEqual(rows[0]["event_end"], "2017-07-03 08:00:01.234567")
        self.assertEqual(len(FEATURES), 27)
        self.assertEqual(headers, ["event_start", "event_end", "source_label", "attempted_category", *[value[0] for value in FEATURES.values()]])
        self.assertEqual(rows[0]["attempted_category"], "raw-attempt-0-8")
        for path in output.iterdir():
            if path.is_file():
                text = path.read_text(encoding="utf-8")
                for sentinel in ("192.0.2.123", "198.51.100.45", "sensitive-endpoint-sentinel", "Src IP", "Dst Port"):
                    self.assertNotIn(sentinel, text)
        config = json.loads((output / "config.json").read_text())
        self.assertEqual(len(config["feature_allowlist"]), 27)
        self.assertEqual(config["timestamp_format"], TIME_FORMAT)
        self.assertEqual(config["profile"], "subset")

    def test_attempted_suffix_is_exact_and_effective_family_mapping_is_explicit(self):
        output = self.prepare()
        config = json.loads((output / "config.json").read_text())
        mapping = config["label_map"]
        self.assertEqual(mapping["BENIGN"], {"binary": 0, "family": "benign"})
        self.assertEqual(mapping["Exploit - Attempted"], {"binary": 0, "family": "benign"})
        for label in ("Exploit", "Exploit - attempted", "Exploit - Attempted extra"):
            self.assertEqual(mapping[label], {"binary": 1, "family": label})
        _, rows = self.read_csv(output / "flows.csv")
        attempted = next(row for row in rows if row["source_label"] == "Exploit - Attempted")
        self.assertTrue(attempted["attempted_category"].startswith("raw-attempt-1-"))
        preparation = json.loads((output / "preparation.json").read_text())
        self.assertEqual(set(preparation["source_label_values"]), set(mapping))

    def test_selected_invalid_numeric_value_is_preserved_then_excluded_by_audit(self):
        self.members["monday.csv"][0]["Fwd IAT Total"] = "NaN"
        self.write_archive()
        output = self.prepare()
        _, rows = self.read_csv(output / "flows.csv")
        self.assertEqual(sum(row["fwd_iat_total"] == "NaN" for row in rows), 1)
        config_path = output / "config.json"
        config = json.loads(config_path.read_text())
        config["output_dir"] = str(self.root / "audit")
        config_path.write_text(json.dumps(config), encoding="utf-8")
        audit = run_audit(config_path)
        quality = json.loads((audit / "quality.json").read_text())["corrected"]
        self.assertEqual(quality["input_rows"], 10)
        self.assertEqual(quality["dispositions"]["excluded"], 1)
        _, splits = self.read_csv(audit / "splits.csv")
        excluded = [row for row in splits if row["disposition"] == "excluded"]
        self.assertEqual(excluded[0]["reason"], "nonfinite_feature:fwd_iat_total")

    def test_sample_is_repeatable_and_selection_matches_member_record_policy(self):
        output = self.prepare(denominator=3)
        first_bytes = (output / "flows.csv").read_bytes()
        provenance = json.loads(self.acquisition.read_text())
        expected = {
            row["Timestamp"] for member, rows in self.members.items()
            for record, row in enumerate(rows, start=2)
            if selected_record(provenance["sha256"], member, record, 3)
        }
        _, rows = self.read_csv(output / "flows.csv")
        self.assertEqual({row["event_start"] for row in rows}, expected)
        self.output = self.root / "prepared-again"
        again = self.prepare(denominator=3)
        self.assertEqual((again / "flows.csv").read_bytes(), first_bytes)
        preparation = json.loads((output / "preparation.json").read_text())
        self.assertEqual(preparation["selected_rows"], len(expected))
        self.assertEqual(sum(value["source_rows"] for value in preparation["by_member"].values()), 10)
        self.assertIn("no balancing", preparation["selection_note"])

    def test_row_cap_fails_without_publishing_a_truncated_sample(self):
        with self.assertRaisesRegex(ValueError, "max_rows"):
            self.prepare(max_rows=9)
        self.assert_no_published_or_staged_output()

    def test_archive_digest_mismatch_is_rejected(self):
        metadata = json.loads(self.acquisition.read_text())
        metadata["sha256"] = "0" * 64
        self.acquisition.write_text(json.dumps(metadata), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            self.prepare()
        self.assert_no_published_or_staged_output()

    def test_unsafe_or_unexpected_members_are_rejected(self):
        for names in ([*DAYS, "../escape.csv"], [*DAYS, "notes.txt"], sorted(DAYS)[:-1]):
            with self.subTest(members=names):
                self.write_archive(names)
                with self.assertRaisesRegex(ValueError, "five"):
                    self.prepare()
                self.assert_no_published_or_staged_output()

    def test_invalid_sampling_limits_are_rejected(self):
        for denominator, cap in ((0, 20), (True, 20), (1, 0), (1, 1.5)):
            with self.subTest(denominator=denominator, cap=cap), self.assertRaises(ValueError):
                self.prepare(denominator, cap)
        self.assert_no_published_or_staged_output()


if __name__ == "__main__":
    unittest.main()
