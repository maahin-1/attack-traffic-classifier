import csv
import json
import tempfile
import unittest
from pathlib import Path

from attack_traffic.inspect_corrected2018 import MEMBER, _fingerprint, inspect_corrected_development, review_proposed_support
from attack_traffic.prepare import FEATURES


class CorrectedInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_root = Path('.test-tmp').resolve()
        cls.temp_root.mkdir(exist_ok=True)

    def fixture(self, folder):
        header = [*FEATURES, 'Label', 'Attempted Category', 'Timestamp']
        header += [f'extra{i}' for i in range(91 - len(header))]
        path = folder / MEMBER
        def row(label, category, stamp, **values):
            record = dict.fromkeys(header, '0')
            record.update(Label=label, Timestamp=stamp, **{'Attempted Category': category}, **values)
            return [record[name] for name in header]
        with path.open('w', newline='', encoding='utf-8') as stream:
            writer = csv.writer(stream)
            writer.writerow(header)
            writer.writerow(row('Benign', '-1', '2018-02-14 12:00:00.000001'))
            writer.writerow(row('FTP-BruteForce - Attempted', '1', '2018-02-14 11:00:00.000001', **{'Flow Duration': '-1', 'Fwd Packet Length Min': '-2'}))
            writer.writerow(row('SSH-BruteForce', '-1', '1970-01-01 00:00:00.000000', **{'Flow IAT Mean': '', 'Idle Mean': 'NaN'}))
            writer.writerow(row('unknown', 'bad', 'bad'))
            writer.writerow(row('', '-1', '2018-02-14 12:01:00.000000'))
            writer.writerow(row('Benign', '7', '2018-02-14 12:02:00.000000'))
            writer.writerow(header)
            writer.writerow(['short'])
        fp = _fingerprint(path)
        manifest = folder / 'acquisition.json'
        manifest.write_text(json.dumps({'file': MEMBER, 'bytes': fp['bytes'], 'sha256': fp['sha256'],
            'member_crc32_verified': fp['crc32'], 'role': 'corrected 2018 development member only; no model scoring'}))
        return path, manifest

    def test_streamed_accounting_and_quality(self):
        with tempfile.TemporaryDirectory(dir=self.temp_root) as temp:
            folder = Path(temp)
            path, manifest = self.fixture(folder)
            output = folder / 'result.json'
            result = inspect_corrected_development(path, manifest, output)
            self.assertEqual(result['counts']['csv_records'], 8)
            self.assertEqual(result['counts']['data_rows'], 6)
            self.assertEqual(result['counts']['rows_invalid_required_features'], 2)
            self.assertEqual(result['counts']['wrong_capture_date'], 1)
            self.assertEqual(result['counts']['invalid_timestamp'], 1)
            self.assertEqual(result['counts']['timestamp_decreases_in_source_order'], 2)
            self.assertEqual(result['proposed_binary_support'], {'benign': 2, 'attack': 1})
            self.assertEqual(result['counts']['unresolved_proposed_binary'], 3)
            self.assertEqual(result['counts']['unknown_or_empty_label'], 2)
            self.assertEqual(result['feature_issues']['Fwd Packet Length Min']['negative'], 1)
            self.assertEqual(result['feature_issues']['Flow IAT Mean']['missing'], 1)
            self.assertEqual(result['feature_issues']['Idle Mean']['nonfinite'], 1)
            with self.assertRaises(ValueError):
                inspect_corrected_development(path, manifest, output)

    def test_manifest_and_schema_fail_closed(self):
        with tempfile.TemporaryDirectory(dir=self.temp_root) as temp:
            folder = Path(temp)
            path, manifest = self.fixture(folder)
            data = json.loads(manifest.read_text())
            data['member_crc32_verified'] = '00000000'
            manifest.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, 'CRC'):
                inspect_corrected_development(path, manifest, folder / 'result.json')
            self.assertFalse((folder / 'result.json').exists())
            path.write_text('Label,Timestamp\nBenign,invalid\n', encoding='utf-8')
            fp = _fingerprint(path)
            data.update(sha256=fp['sha256'], bytes=fp['bytes'], member_crc32_verified=fp['crc32'])
            manifest.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, '91 unique'):
                inspect_corrected_development(path, manifest, folder / 'result.json')

    def test_explicit_uppercase_alias_and_reviewed_support(self):
        with tempfile.TemporaryDirectory(dir=self.temp_root) as temp:
            folder = Path(temp)
            path, manifest = self.fixture(folder)
            with path.open(newline='', encoding='utf-8') as stream:
                rows = list(csv.reader(stream))
            header = rows[0]
            benign, attack = list(rows[1]), list(rows[3])
            benign[header.index('Label')] = 'BENIGN'
            benign[header.index('Timestamp')] = '2018-02-15 00:01:00.000000'
            attack[header.index('Timestamp')] = '2018-02-14 19:00:00.000000'
            for name in ('Flow IAT Mean', 'Idle Mean'):
                attack[header.index(name)] = '0'
            with path.open('w', newline='', encoding='utf-8') as stream:
                csv.writer(stream).writerows([header, benign, attack])
            data = json.loads(manifest.read_text())
            fp = _fingerprint(path)
            data.update(sha256=fp['sha256'], bytes=fp['bytes'], member_crc32_verified=fp['crc32'])
            manifest.write_text(json.dumps(data))
            inventory_path = folder / 'inventory.json'
            result = inspect_corrected_development(path, manifest, inventory_path)
            self.assertEqual(result['proposed_binary_support'], {'benign': 1, 'attack': 1})
            reviewed = review_proposed_support(inventory_path, manifest, folder / 'reviewed.json')
            self.assertEqual(reviewed['cross_date_rows'], 1)
            self.assertEqual(reviewed['proposed_binary_support'], {'benign': 1, 'attack': 1})
            result['label_category_support'][0]['rows'] += 1
            inventory_path.write_text(json.dumps(result))
            with self.assertRaisesRegex(ValueError, 'reconciliation'):
                review_proposed_support(inventory_path, manifest, folder / 'bad.json')


if __name__ == '__main__':
    unittest.main()
