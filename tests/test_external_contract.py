import csv
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from attack_traffic.external_contract import validate_external_contract
from attack_traffic.prepare import FEATURES
from attack_traffic.support_extract import feature_digest


class ExternalContractTests(unittest.TestCase):
    def setUp(self):
        scratch = Path(__file__).resolve().parent.parent / '.test-tmp'
        scratch.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.csv = self.root / 'external.csv'
        self.manifest_path = self.root / 'manifest.json'
        self.splits = self.root / 'splits.csv'
        self.features = [item[0] for item in FEATURES.values()]
        self.units = {item[0]: item[1] for item in FEATURES.values()}
        self.row = ['r1', 'attack', *(['1'] * len(self.features))]
        self.manifest = {'schema_version': 1, 'source_name': 'synthetic',
                         'source_url': 'https://example.test', 'capture_description': 'fixture',
                         'independence_attestation': 'separate synthetic capture',
                         'feature_units': self.units, 'label_map': {'attack': 1, 'benign': 0}}
        self.splits.write_text('duplicate_group_id\n' + feature_digest([2.0] * len(self.features)) + '\n')
        self.split_hash = hashlib.sha256(self.splits.read_bytes()).hexdigest()
        self.write_csv()

    def write_csv(self, header=None, rows=None):
        with self.csv.open('w', newline='', encoding='utf-8') as stream:
            writer = csv.writer(stream)
            writer.writerow(header if header is not None else ['record_id', 'source_label', *self.features])
            writer.writerows(rows if rows is not None else [self.row])
        self.manifest['csv_sha256'] = hashlib.sha256(self.csv.read_bytes()).hexdigest()

    def validate(self):
        self.manifest_path.write_text(json.dumps(self.manifest), encoding='utf-8')
        return validate_external_contract(self.csv, self.manifest_path, self.splits, self.split_hash)

    def test_pass_and_no_metrics(self):
        result = self.validate()
        self.assertEqual(result['status'], 'contract_checks_passed')
        self.assertEqual(result['rows'], 1)
        self.assertNotIn('recall', result)

    def test_missing_or_extra_features_rejected(self):
        for header in (['record_id', 'source_label', *self.features[:-1]], ['record_id', 'source_label', *self.features, 'extra']):
            with self.subTest(header=header):
                self.write_csv(header=header)
                with self.assertRaisesRegex(ValueError, 'schema'):
                    self.validate()

    def test_units_and_attestation_required(self):
        self.manifest['feature_units'] = {}
        with self.assertRaisesRegex(ValueError, 'units'):
            self.validate()
        self.manifest['feature_units'] = self.units
        self.manifest['independence_attestation'] = ''
        with self.assertRaisesRegex(ValueError, 'attestation'):
            self.validate()

    def test_unknown_label_duplicate_id_and_nonfinite(self):
        for rows, message in (([['r1', 'unknown', *(['1'] * len(self.features))]], 'label'),
                              ([self.row, self.row], 'record ID'),
                              ([['r1', 'attack', 'nan', *(['1'] * (len(self.features) - 1))]], 'feature')):
            with self.subTest(message=message):
                self.write_csv(rows=rows)
                with self.assertRaisesRegex(ValueError, message):
                    self.validate()

    def test_frozen_group_match_rejected(self):
        self.write_csv(rows=[['r1', 'attack', *(['2'] * len(self.features))]])
        with self.assertRaisesRegex(ValueError, 'matches'):
            self.validate()

    def test_hash_tamper_rejected(self):
        self.manifest['csv_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'CSV hash'):
            self.validate()
        self.manifest['csv_sha256'] = hashlib.sha256(self.csv.read_bytes()).hexdigest()
        self.splits.write_text('duplicate_group_id\n')
        with self.assertRaisesRegex(ValueError, 'split hash'):
            self.validate()


if __name__ == '__main__':
    unittest.main()
