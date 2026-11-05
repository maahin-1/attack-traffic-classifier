import csv
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from attack_traffic.inspect_ids2018 import ALIASES, FILENAME, inspect_development


class InspectTests(unittest.TestCase):
    def test_inventory_and_guards(self):
        Path('.test-tmp').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir='.test-tmp') as tmp:
            root = Path(tmp)
            source = root / FILENAME
            with source.open('w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                header = [*ALIASES, 'Label']
                writer.writerow(header)
                writer.writerow(['1'] * 27 + ['Benign'])
                writer.writerow(['inf'] + ['1'] * 26 + ['Attack'])
                writer.writerow(header)
                writer.writerow(['broken'])
            acquisition = root / 'acquisition.json'
            acquisition.write_text(json.dumps({'file': FILENAME, 'bytes': source.stat().st_size,
                'sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                'role': 'development schema inspection only'}))
            out = root / 'inventory.json'
            result = inspect_development(source, acquisition, out)
            self.assertEqual(result['records']['data_rows'], 2)
            self.assertEqual(result['records']['malformed_width'], 1)
            self.assertEqual(result['records']['embedded_header'], 1)
            self.assertEqual(result['records']['rows_invalid_required_features'], 1)
            self.assertEqual(result['labels'], {'Attack': 1, 'Benign': 1})
            self.assertEqual(result['invalid_feature_values']['Flow Duration'], 1)
            with self.assertRaises(ValueError):
                inspect_development(source, acquisition, out)
            source.write_text('tampered')
            with self.assertRaises(ValueError):
                inspect_development(source, acquisition, root / 'other.json')
