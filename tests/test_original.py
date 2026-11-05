"""Publisher-original ZIP adapter tests; no real capture files are needed."""

import csv
import hashlib
import io
import json
from datetime import datetime
from pathlib import Path
import tempfile
import unittest
import zipfile

from attack_traffic.original import ORIGINAL_FEATURES, ORIGINAL_MEMBERS, inspect_original


# Exact publisher header order, including the duplicated metadata column.
PUBLISHER_HEADERS = [
    "Flow ID", " Source IP", " Source Port", " Destination IP", " Destination Port", " Protocol", " Timestamp",
    " Flow Duration", " Total Fwd Packets", " Total Backward Packets", "Total Length of Fwd Packets", " Total Length of Bwd Packets",
    " Fwd Packet Length Max", " Fwd Packet Length Min", " Fwd Packet Length Mean", " Fwd Packet Length Std",
    "Bwd Packet Length Max", " Bwd Packet Length Min", " Bwd Packet Length Mean", " Bwd Packet Length Std",
    "Flow Bytes/s", " Flow Packets/s", " Flow IAT Mean", " Flow IAT Std", " Flow IAT Max", " Flow IAT Min",
    "Fwd IAT Total", " Fwd IAT Mean", " Fwd IAT Std", " Fwd IAT Max", " Fwd IAT Min", "Bwd IAT Total", " Bwd IAT Mean", " Bwd IAT Std", " Bwd IAT Max", " Bwd IAT Min",
    "Fwd PSH Flags", " Bwd PSH Flags", " Fwd URG Flags", " Bwd URG Flags", " Fwd Header Length", " Bwd Header Length",
    "Fwd Packets/s", " Bwd Packets/s", " Min Packet Length", " Max Packet Length", " Packet Length Mean", " Packet Length Std", " Packet Length Variance",
    "FIN Flag Count", " SYN Flag Count", " RST Flag Count", " PSH Flag Count", " ACK Flag Count", " URG Flag Count", " CWE Flag Count", " ECE Flag Count",
    " Down/Up Ratio", " Average Packet Size", " Avg Fwd Segment Size", " Avg Bwd Segment Size", " Fwd Header Length",
    "Fwd Avg Bytes/Bulk", " Fwd Avg Packets/Bulk", " Fwd Avg Bulk Rate", " Bwd Avg Bytes/Bulk", " Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets", " Subflow Fwd Bytes", " Subflow Bwd Packets", " Subflow Bwd Bytes", "Init_Win_bytes_forward", " Init_Win_bytes_backward", " act_data_pkt_fwd", " min_seg_size_forward",
    "Active Mean", " Active Std", " Active Max", " Active Min", "Idle Mean", " Idle Std", " Idle Max", " Idle Min", " Label",
]


class OriginalAdapterTests(unittest.TestCase):
    def setUp(self):
        self.repo = Path(__file__).resolve().parent.parent
        scratch = self.repo / ".test-tmp"
        scratch.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = self.root / "original.zip"
        self.acquisition = self.root / "acquisition.json"
        self.output = self.root / "inventory.json"
        self.members = {}
        for index, name in enumerate(sorted(ORIGINAL_MEMBERS)):
            if "Monday" in name:
                timestamp = "03/07/2017 08:55:58"
            elif "Tuesday" in name:
                timestamp = "4/7/2017 8:54"
            elif "Wednesday" in name:
                timestamp = "5/7/2017 1:00"
            elif "Thursday" in name:
                timestamp = "6/7/2017 1:00"
            else:
                timestamp = "7/7/2017 3:30"
            row = []
            for header in PUBLISHER_HEADERS:
                stripped = header.strip()
                value = str(index * 100 + 10)
                if stripped == "Timestamp":
                    value = timestamp
                elif stripped == "Label":
                    value = "Web Attack – Brute Force" if "Thursday" in name else "BENIGN"
                elif stripped in ("Flow ID", "Source IP", "Destination IP"):
                    value = "endpoint-sentinel-192.0.2.10"
                elif stripped == "Flow Duration":
                    value = "1234567"
                row.append(value)
            self.members[name] = [row]
        self.write_archive()

    def write_archive(self, member_names=None):
        with zipfile.ZipFile(self.archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            bundle.writestr("TrafficLabelling /", "")
            for name in member_names or self.members:
                text = io.StringIO(newline="")
                writer = csv.writer(text)
                writer.writerow(PUBLISHER_HEADERS)
                writer.writerows(self.members.get(name, []))
                bundle.writestr(name, text.getvalue().encode("cp1252"))
        metadata = {
            "variant": "original", "release": "synthetic-original-test",
            "sha256": hashlib.sha256(self.archive.read_bytes()).hexdigest(),
            "source_url": "synthetic://publisher-layout-fixture",
            "retrieved_at": "2026-11-02T00:00:00Z",
            "license_status": "Project-authored synthetic fixture",
        }
        self.acquisition.write_text(json.dumps(metadata), encoding="utf-8")

    def inspect(self):
        return inspect_original(self.archive, self.acquisition, self.output)

    @staticmethod
    def read_csv(path):
        with path.open(newline="", encoding="utf-8") as stream:
            reader = csv.DictReader(stream)
            return reader.fieldnames, list(reader)

    def prepare(self, denominator=1, max_rows=20, name="subset"):
        from attack_traffic.original import prepare_original_subset
        return prepare_original_subset(self.archive, self.acquisition, self.root / name, denominator, max_rows)

    def set_field(self, member, name, value, record=0):
        index = next(i for i, header in enumerate(PUBLISHER_HEADERS) if header.strip() == name)
        self.members[member][record][index] = value

    def test_fixture_reproduces_duplicate_positional_headers_and_common_feature_policy(self):
        self.assertEqual(len(PUBLISHER_HEADERS), 85)
        self.assertEqual(sum(header.strip() == "Fwd Header Length" for header in PUBLISHER_HEADERS), 2)
        self.assertEqual(len(ORIGINAL_FEATURES), 27)
        from attack_traffic.prepare import FEATURES
        self.assertEqual(set(ORIGINAL_FEATURES.values()), set(FEATURES.values()))
        self.assertNotIn("Fwd Header Length", ORIGINAL_FEATURES)

    def test_inspection_decodes_cp1252_labels_without_exporting_endpoint_values(self):
        output = self.inspect()
        self.assertEqual(output, self.output)
        contents = json.dumps(json.loads(output.read_text(encoding="utf-8")), ensure_ascii=False)
        self.assertIn("Web Attack – Brute Force", contents)
        self.assertNotIn("endpoint-sentinel-192.0.2.10", contents)

    def test_inventory_output_is_immutable(self):
        self.inspect()
        before = self.output.read_bytes()
        with self.assertRaises(ValueError):
            self.inspect()
        self.assertEqual(self.output.read_bytes(), before)

    def test_acquisition_hash_mismatch_fails_before_publishing(self):
        metadata = json.loads(self.acquisition.read_text())
        metadata["sha256"] = "0" * 64
        self.acquisition.write_text(json.dumps(metadata), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "(?i)(sha|hash|digest)"):
            self.inspect()
        self.assertFalse(self.output.exists())

    def test_unexpected_and_unsafe_members_are_rejected(self):
        for names in ([*ORIGINAL_MEMBERS, "../escaped.csv"], [*ORIGINAL_MEMBERS, "notes.txt"], sorted(ORIGINAL_MEMBERS)[:-1]):
            with self.subTest(members=names):
                self.write_archive(names)
                with self.assertRaises(ValueError):
                    self.inspect()
                self.assertFalse(self.output.exists())

    def test_positional_field_count_mismatch_is_rejected(self):
        name = next(iter(self.members))
        self.members[name][0].pop()
        self.write_archive()
        with self.assertRaises(ValueError):
            self.inspect()
        self.assertFalse(self.output.exists())

    def test_clock_inventory_retains_precision_date_candidates_and_missing_ampm(self):
        output = self.inspect()
        inventory = json.loads(output.read_text())
        self.assertEqual(inventory["total_rows"], 8)
        self.assertEqual(inventory["encoding"], "cp1252")
        self.assertIn("unresolved", inventory["clock_policy"])
        monday = next(value for name, value in inventory["members"].items() if "Monday" in name)
        self.assertEqual(monday["timestamp_precision_counts"], {"second": 1})
        self.assertEqual(monday["ampm_marker_counts"], {"missing": 1})
        self.assertEqual(monday["raw_hour_counts"], {"8": 1})
        self.assertIn("day_month_year|2017-07-03|Monday", monday["date_candidate_counts"])
        self.assertIn("month_day_year|2017-03-07|Tuesday", monday["date_candidate_counts"])
        wednesday = next(value for name, value in inventory["members"].items() if "Wednesday" in name)
        self.assertEqual(wednesday["timestamp_precision_counts"], {"minute": 1})
        self.assertEqual(wednesday["label_hour_counts"], {"BENIGN": {"1": 1}})

    def test_duplicate_metadata_is_read_positionally_and_never_silently_collapsed(self):
        name = next(iter(self.members))
        positions = [i for i, header in enumerate(PUBLISHER_HEADERS) if header.strip() == "Fwd Header Length"]
        self.members[name][0][positions[0]] = "17"
        self.members[name][0][positions[1]] = "99"
        self.write_archive()
        inventory = json.loads(self.inspect().read_text())
        evidence = inventory["members"][name]["duplicate_fwd_header_length"]
        self.assertEqual(evidence["zero_based_positions"], [40, 61])
        self.assertEqual(evidence["counts"]["text_unequal"], 1)
        self.assertEqual(evidence["counts"]["numeric_unequal"], 1)
        self.assertEqual(evidence["unequal_examples"], [{"source_record": 2, "left": "17", "right": "99"}])

    def test_numeric_quality_inventory_counts_rows_without_dropping_them(self):
        name = next(iter(self.members))
        duration_index = next(i for i, header in enumerate(PUBLISHER_HEADERS) if header.strip() == "Flow Duration")
        self.members[name][0][duration_index] = "NaN"
        self.write_archive()
        inventory = json.loads(self.inspect().read_text())
        self.assertEqual(inventory["total_rows"], 8)
        evidence = inventory["members"][name]
        self.assertEqual(evidence["source_rows"], 1)
        self.assertEqual(evidence["counts"]["rows_invalid_required_numeric"], 1)
        self.assertEqual(evidence["required_numeric_issues"]["nan|Flow Duration"], 1)

    def test_prepared_subset_has_exact_feature_aliases_source_references_and_no_endpoints(self):
        output = self.prepare()
        headers, rows = self.read_csv(output / "flows.csv")
        self.assertEqual(len(rows), 8)
        config = json.loads((output / "config.json").read_text())
        self.assertEqual(set(config["feature_allowlist"]), {value[0] for value in ORIGINAL_FEATURES.values()})
        self.assertEqual(len(config["feature_allowlist"]), 27)
        self.assertEqual(config["temporal_basis"], "capture_date")
        self.assertEqual(config["timezone"], "unresolved")
        self.assertEqual(len({(row["origin_member"], row["origin_record"]) for row in rows}), 8)
        for row in rows:
            member, record = row["origin_member"], int(row["origin_record"])
            self.assertIn(member, ORIGINAL_MEMBERS)
            self.assertEqual(record, 2)
            source = self.members[member][record - 2]
            for source_name, (canonical, _) in ORIGINAL_FEATURES.items():
                index = next(i for i, header in enumerate(PUBLISHER_HEADERS) if header.strip() == source_name)
                self.assertEqual(row[canonical], source[index])
            self.assertEqual(row["event_start"], "")
            self.assertEqual(row["event_end"], "")
        self.assertNotIn("Source IP", headers)
        self.assertNotIn("Fwd Header Length", headers)
        self.assertNotIn("endpoint-sentinel", (output / "flows.csv").read_text())
        web = [row for row in rows if "Thursday" in row["origin_member"]]
        self.assertTrue(all(row["source_label"] == "Web Attack – Brute Force" for row in web))

    def test_missing_ampm_and_timestamp_precision_form_conservative_local_bounds(self):
        wednesday = next(name for name in self.members if "Wednesday" in name)
        thursday = next(name for name in self.members if "Thursday" in name)
        self.set_field(wednesday, "Timestamp", "5/7/2017 1:00")
        self.set_field(thursday, "Timestamp", "6/7/2017 12:00")
        self.write_archive()
        _, rows = self.read_csv(self.prepare() / "flows.csv")
        by_member = {row["origin_member"]: row for row in rows}
        lower = datetime.fromisoformat(by_member[wednesday]["local_start_lower"])
        upper = datetime.fromisoformat(by_member[wednesday]["local_start_upper"])
        end = datetime.fromisoformat(by_member[wednesday]["local_end_upper"])
        self.assertEqual(lower, datetime(2017, 7, 5, 1, 0))
        self.assertEqual(upper, datetime(2017, 7, 5, 13, 0, 59, 999999))
        self.assertEqual((end - upper).total_seconds(), 1.234567)
        self.assertIsNone(lower.tzinfo)
        self.assertEqual(datetime.fromisoformat(by_member[thursday]["local_start_lower"]), datetime(2017, 7, 6, 0, 0))
        self.assertEqual(datetime.fromisoformat(by_member[thursday]["local_start_upper"]), datetime(2017, 7, 6, 12, 0, 59, 999999))
        monday = next(row for row in rows if "Monday" in row["origin_member"])
        self.assertEqual(datetime.fromisoformat(monday["local_start_upper"]), datetime(2017, 7, 3, 20, 55, 58, 999999))
        self.assertEqual(monday["capture_date"], "2017-07-03")

    def test_original_sample_is_repeatable_and_uses_archive_member_record_selector(self):
        from attack_traffic.prepare import selected_record
        digest = json.loads(self.acquisition.read_text())["sha256"]
        expected = {(name, "2") for name in self.members if selected_record(digest, name, 2, 3)}
        first = self.prepare(denominator=3)
        _, rows = self.read_csv(first / "flows.csv")
        self.assertEqual({(row["origin_member"], row["origin_record"]) for row in rows}, expected)
        second = self.prepare(denominator=3, name="repeat-subset")
        self.assertEqual((first / "flows.csv").read_bytes(), (second / "flows.csv").read_bytes())

    def test_original_subset_is_immutable_and_cap_failure_does_not_publish(self):
        with self.assertRaisesRegex(ValueError, "max_rows"):
            self.prepare(max_rows=7)
        self.assertFalse((self.root / "subset").exists())
        self.assertFalse(list(self.root.glob(".original-prepare-*")))
        output = self.prepare()
        before = {p.name: p.read_bytes() for p in output.iterdir() if p.is_file()}
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertEqual(before, {p.name: p.read_bytes() for p in output.iterdir() if p.is_file()})

    def test_selected_invalid_feature_is_preserved_then_audited_out(self):
        from attack_traffic import run_audit
        name = next(iter(self.members))
        self.set_field(name, "Fwd IAT Total", "NaN")
        self.write_archive()
        output = self.prepare()
        _, rows = self.read_csv(output / "flows.csv")
        self.assertEqual(sum(row["fwd_iat_total"] == "NaN" for row in rows), 1)
        config_path = output / "config.json"
        config = json.loads(config_path.read_text())
        config["output_dir"] = str(self.root / "audit")
        config_path.write_text(json.dumps(config), encoding="utf-8")
        audit = run_audit(config_path)
        quality = json.loads((audit / "quality.json").read_text())["original"]
        self.assertEqual(quality["input_rows"], 8)
        self.assertEqual(quality["dispositions"]["excluded"], 1)

    def test_possible_interval_crossing_capture_day_boundary_is_quarantined(self):
        from attack_traffic import run_audit
        name = next(name for name in self.members if "Tuesday" in name)
        self.set_field(name, "Timestamp", "4/7/2017 11:59")
        self.write_archive()
        output = self.prepare()
        config_path = output / "config.json"
        config = json.loads(config_path.read_text())
        config["output_dir"] = str(self.root / "audit")
        config_path.write_text(json.dumps(config), encoding="utf-8")
        audit = run_audit(config_path)
        _, rows = self.read_csv(audit / "splits.csv")
        crossing = next(row for row in rows if row["origin_member"] == name)
        self.assertEqual(crossing["partition"], "train")
        self.assertEqual(crossing["disposition"], "quarantined")
        self.assertIn("boundary", crossing["reason"])

    def test_original_clock_date_inconsistency_is_rejected_instead_of_guessed(self):
        name = next(name for name in self.members if "Tuesday" in name)
        self.set_field(name, "Timestamp", "5/7/2017 8:54")
        self.write_archive()
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertFalse((self.root / "subset").exists())

    def test_all_empty_source_padding_is_accounted_separately_with_original_ordinals(self):
        name = next(iter(self.members))
        real_row = self.members[name][0][:]
        self.members[name] = [[""] * 85, real_row, [" "] * 85]
        self.write_archive()
        output = self.prepare()
        _, rows = self.read_csv(output / "flows.csv")
        selected_real = next(row for row in rows if row["origin_member"] == name)
        self.assertEqual(selected_real["origin_record"], "3")
        self.assertEqual(len(rows), 8)
        _, exclusions = self.read_csv(output / "preparation_exclusions.csv")
        self.assertEqual(len(exclusions), 2)
        self.assertEqual({row["origin_record"] for row in exclusions}, {"2", "4"})
        for row in exclusions:
            self.assertEqual(row["origin_member"], name)
            self.assertEqual(row["source_label_class"], "<missing>")
            self.assertEqual(row["reason"], "all_85_fields_empty_source_padding")
            self.assertEqual(row["selected"], "True")
        preparation = json.loads((output / "preparation.json").read_text())
        self.assertEqual(preparation["source_input_rows"], 10)
        self.assertEqual(preparation["source_empty_excluded_rows"], 2)
        self.assertEqual(preparation["selected_empty_rows"], 2)
        self.assertEqual(preparation["source_input_rows"], preparation["source_empty_excluded_rows"] + preparation["selected_flow_rows"] + preparation["unsampled_flow_rows"])
        config = json.loads((output / "config.json").read_text())
        self.assertNotIn("", config["label_map"])
        self.assertNotIn("<missing>", config["label_map"])

    def test_padding_selection_uses_original_hash_ordinals_without_compaction(self):
        from attack_traffic.prepare import selected_record
        name = next(iter(self.members))
        self.members[name].insert(0, [""] * 85)
        self.write_archive()
        digest = json.loads(self.acquisition.read_text())["sha256"]
        output = self.prepare(denominator=3)
        _, exclusions = self.read_csv(output / "preparation_exclusions.csv")
        self.assertEqual(len(exclusions), 1)
        self.assertEqual(exclusions[0]["selected"], str(selected_record(digest, name, 2, 3)))
        _, rows = self.read_csv(output / "flows.csv")
        matching = [row for row in rows if row["origin_member"] == name]
        self.assertEqual(bool(matching), selected_record(digest, name, 3, 3))
        if matching:
            self.assertEqual(matching[0]["origin_record"], "3")

    def test_missing_label_on_nonempty_flow_fails_instead_of_becoming_benign(self):
        name = next(iter(self.members))
        self.set_field(name, "Label", "")
        self.write_archive()
        with self.assertRaisesRegex(ValueError, "(?i)label"):
            self.prepare()
        self.assertFalse((self.root / "subset").exists())


if __name__ == "__main__":
    unittest.main()
