import hashlib
import json
import tempfile
import unittest
import csv
import io
import zipfile
from pathlib import Path
from unittest.mock import patch

from attack_traffic.prepare import selected_record
from attack_traffic.support_extract import extract_training_support, feature_digest
from attack_traffic.prepare import FEATURES
from attack_traffic.original import ORIGINAL_MEMBERS
from attack_traffic.tune import SOURCE_FILES
from test_original import PUBLISHER_HEADERS


class TrainingSupportTests(unittest.TestCase):
    def test_feature_digest_matches_audit_and_normalizes_negative_zero(self):
        values = [-0.0, 1.25, -2.0]
        expected = hashlib.sha256(json.dumps([0.0, 1.25, -2.0], separators=(',', ':'), allow_nan=False).encode()).hexdigest()
        self.assertEqual(feature_digest(values), expected)

    def test_nested_selection_excludes_all_old_records(self):
        digest = '0' * 64
        old = {i for i in range(2, 10002) if selected_record(digest, 'tuesday.csv', i, 100)}
        added = {i for i in range(2, 10002) if selected_record(digest, 'tuesday.csv', i, 10) and not selected_record(digest, 'tuesday.csv', i, 100)}
        self.assertTrue(old)
        self.assertTrue(added)
        self.assertFalse(old & added)
        self.assertTrue(all(selected_record(digest, 'tuesday.csv', i, 10) for i in old))

    def test_changed_source_blocks_before_reading_archives(self):
        scratch = Path(__file__).resolve().parent.parent / '.test-tmp'
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as tmp:
            base = Path(tmp)
            source = base / 'source'
            source.mkdir()
            ref = base / 'experiment-004-features'
            ref.mkdir()
            (ref / 'provenance.json').write_text('{"source_files": {}}', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'provenance'):
                extract_training_support(source, 'x', 'x', 'x', 'x', base / 'out')
            self.assertFalse((base / 'out').exists())

    def test_archive_flow_blocks_holdout_and_deduplicates(self):
        scratch = Path(__file__).resolve().parent.parent / '.test-tmp'
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as tmp:
            base = Path(tmp)
            source = base / 'source'
            (source / 'audit').mkdir(parents=True)
            original, corrected = base / 'original.zip', base / 'corrected.zip'
            def csvbytes(header, rows, encoding):
                buf = io.StringIO(newline='')
                writer = csv.writer(buf)
                writer.writerow(header)
                writer.writerows(rows)
                return buf.getvalue().encode(encoding)
            with zipfile.ZipFile(original, 'w') as z:
                for member in sorted(ORIGINAL_MEMBERS):
                    day = '3' if 'Monday' in member else '4'
                    rows = []
                    for value in ('0', '1', '1', '2'):
                        rows.append([f'{day}/7/2017 08:00' if h.strip() == 'Timestamp' else 'FTP-Patator' if h.strip() == 'Label' else '999999999999' if value == '2' and h.strip() == 'Flow Duration' else value for h in PUBLISHER_HEADERS])
                    z.writestr(member, csvbytes(PUBLISHER_HEADERS, rows, 'cp1252'))
            headers = ['Timestamp', 'Label', *FEATURES]
            with zipfile.ZipFile(corrected, 'w') as z:
                for day, date in [('monday', '03'), ('tuesday', '04'), ('wednesday', '05'), ('thursday', '06'), ('friday', '07')]:
                    rows = [[f'2017-07-{date} 08:00:00.000000', 'FTP-Patator', *(['999999999999'] + [v] * 26 if v == '2' else [v] * 27)] for v in ('0', '1', '1', '2')]
                    z.writestr(day + '.csv', csvbytes(headers, rows, 'utf-8'))
            datasets = []
            acquisitions = []
            for variant, archive in [('original', original), ('corrected', corrected)]:
                digest = hashlib.sha256(archive.read_bytes()).hexdigest()
                acquisition = base / (variant + '.json')
                acquisition.write_text(json.dumps({'sha256': digest}), encoding='utf-8')
                acquisitions.append(acquisition)
                datasets.append({'variant': variant, 'preparation': {'archive_sha256': digest, 'denominator': 100}, 'label_map': {'FTP-Patator': {'binary': 1, 'family': 'FTP-Patator'}}})
            config = {'temporal_basis': 'capture_date', 'boundaries': {'validation_start': '2017-07-05'}, 'feature_allowlist': [v[0] for v in FEATURES.values()], 'datasets': datasets, 'label_map': {}}
            (source / 'config.json').write_text(json.dumps(config), encoding='utf-8')
            for name in SOURCE_FILES:
                path = source / name
                if not path.exists():
                    path.write_text('', encoding='utf-8')
            with (source / 'audit/splits.csv').open('w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['variant', 'partition', 'duplicate_group_id', 'origin_member', 'origin_record'])
                writer.writeheader()
                for variant in ('original', 'corrected'):
                    writer.writerow(dict(variant=variant, partition='test', duplicate_group_id=feature_digest([0.0] * 27), origin_member='ignored', origin_record='2'))
            ref = base / 'experiment-004-features'
            ref.mkdir()
            (ref / 'provenance.json').write_text(json.dumps({'source_files': {name: hashlib.sha256((source / name).read_bytes()).hexdigest() for name in SOURCE_FILES}}), encoding='utf-8')
            selected = lambda digest, member, ordinal, denominator: denominator == 10
            original_open = zipfile.ZipFile.open
            def only_early(bundle, name, *args, **kwargs):
                self.assertTrue(Path(name).name.lower().startswith(('monday', 'tuesday')))
                return original_open(bundle, name, *args, **kwargs)
            with patch('attack_traffic.support_extract.selected_record', side_effect=selected), patch.object(zipfile.ZipFile, 'open', only_early):
                output = extract_training_support(source, original, acquisitions[0], corrected, acquisitions[1], base / 'out')
            summary = json.loads((output / 'summary.json').read_text())
            for variant in ('original', 'corrected'):
                counts = summary['counts'][variant]
                self.assertEqual(counts['nested_selected'], 8)
                self.assertEqual(counts['retained'], 1)
                self.assertEqual(counts['retained_attack'], 1)
                self.assertEqual(counts['existing_group_quarantine'], 5)
                self.assertEqual(counts['boundary_quarantine'], 2)
            with (output / 'exclusions.csv').open(newline='', encoding='utf-8') as f:
                self.assertEqual(len(list(csv.DictReader(f))), 14)
            with self.assertRaisesRegex(ValueError, 'already exists'):
                extract_training_support(source, original, acquisitions[0], corrected, acquisitions[1], output)


if __name__ == '__main__':
    unittest.main()
