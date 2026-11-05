import csv
import json
import tempfile
import unittest
from pathlib import Path
from attack_traffic.coverage_ids2018 import inspect_coverage, audit_coverage
from attack_traffic.tune import _sha


class CoverageTests(unittest.TestCase):
    def test_coverage_unsorted_invalid_and_acquisition(self):
        Path('.test-tmp').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir='.test-tmp') as tmp:
            p = Path(tmp)/'fixture.csv'
            with p.open('w', newline='') as stream:
                csv.writer(stream).writerows([['Timestamp', 'Label'], ['15/02/2018 11:01:00', 'A'], ['Timestamp', 'Label'], ['15/02/2018 09:00:00', 'A'], ['bad', 'B'], ['bad']])
            a = Path(tmp)/'acquisition.json'
            a.write_text(json.dumps({'file': p.name, 'bytes': p.stat().st_size, 'sha256': _sha(p)}))
            result = inspect_coverage(p, a)
            self.assertEqual(result['counts']['csv_records'], 5)
            self.assertEqual(result['counts']['clock_decreases_in_source_order'], 1)
            self.assertEqual(result['counts']['repeated_header'], 1)
            self.assertEqual(result['counts']['malformed_width'], 1)
            self.assertEqual(result['per_label']['A']['minimum_clock'], '2018-02-15T09:00:00')
            self.assertEqual(result['per_label']['B']['invalid_timestamp'], 1)
            p.write_text('changed')
            with self.assertRaises(ValueError):
                inspect_coverage(p, a)

    def test_reserved_names_and_commitment(self):
        Path('.test-tmp').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir='.test-tmp') as tmp:
            root = Path(tmp)
            reserved = root/'reserved'
            reserved.mkdir()
            for name in ('wrong-a.csv', 'wrong-b.csv'):
                (reserved/name).write_text('bad')
            with self.assertRaisesRegex(ValueError, 'exact 15 and 16'):
                audit_coverage(root, root/'output.json', root/'missing.json')
            for p in reserved.glob('*.csv'):
                p.unlink()
            hashes = {}
            for name in ('Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv', 'Friday-16-02-2018_TrafficForML_CICFlowMeter.csv'):
                (reserved/name).write_text('bad')
                Path(str(reserved/name)+'.acquisition.json').write_text('{}')
                hashes[name] = '0'*64
            commitment = root/'commitment.json'
            commitment.write_text(json.dumps({'data_sha256': hashes, 'acquisition_sha256': hashes}))
            with self.assertRaisesRegex(ValueError, 'pre-scoring commitment'):
                audit_coverage(root, root/'output.json', commitment)
