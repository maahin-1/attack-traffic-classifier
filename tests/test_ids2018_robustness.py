import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np

from attack_traffic import ids2018_robustness as runner
from attack_traffic.support_extract import feature_digest
from attack_traffic.tune import _sha


class RobustnessTests(unittest.TestCase):
    def setUp(self):
        scratch = Path(__file__).resolve().parent.parent / '.test-tmp'
        scratch.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = self.root / 'data'
        self.model = self.root / 'model'
        self.source = self.root / 'source'
        self.data.mkdir()
        (self.source / 'audit').mkdir(parents=True)
        self.model.mkdir()
        self.group = feature_digest([0.0] * len(runner.ALIASES))
        self.split = self.source / 'audit/splits.csv'
        self.split.write_text('duplicate_group_id\n' + self.group + '\n')
        variants = {}
        for variant in ('original', 'corrected'):
            directory = self.model / variant
            directory.mkdir()
            (directory / 'metadata.json').write_text('{}')
            (directory / 'bundle.joblib').write_bytes(b'dummy')
            variants[variant] = {'bundle_sha256': _sha(directory / 'bundle.joblib'), 'threshold': 0.5}
        (self.model / 'provenance.json').write_text(json.dumps({
            'bundle_type': 'binary_random_forest_v1', 'variants': variants,
            'source_files': {'audit/splits.csv': _sha(self.split)}}))
        for name in runner.FILES:
            self.write_data(name)
        self.commitment = self.root / 'commitment.json'
        self.write_commitment()

    def write_commitment(self):
        model_hashes = {f'{variant}/{name}': _sha(self.model / variant / name)
                        for variant in ('original', 'corrected')
                        for name in ('metadata.json', 'bundle.joblib')}
        model_hashes['provenance.json'] = _sha(self.model / 'provenance.json')
        self.commitment.write_text(json.dumps({
            'schema_version': 1,
            'data_sha256': {name: _sha(self.data / name) for name in runner.FILES},
            'acquisition_sha256': {name: _sha(self.data / (name + '.acquisition.json')) for name in runner.FILES},
            'model_sha256': model_hashes,
            'source_sha256': {'audit/splits.csv': _sha(self.split)},
            'protocol_sha256': _sha(Path(runner.__file__).resolve().parent.parent / 'docs/IDS2018-ROBUSTNESS-PROTOCOL.md'),
            'runner_sha256': _sha(Path(runner.__file__).resolve()),
            'dependency_sha256': {name: _sha(Path(runner.__file__).resolve().parent.parent / name)
                                  for name in runner.DEPENDENCIES},
        }))

    def write_data(self, name, unknown=False):
        path = self.data / name
        with path.open('w', newline='', encoding='utf-8') as stream:
            writer = csv.writer(stream)
            header = runner.ALIASES + ['Label']
            writer.writerow(header)
            writer.writerow([0] * 27 + ['Benign'])
            writer.writerow([1] * 27 + [('unexpected' if unknown else 'DoS attacks-Hulk')])
            writer.writerow(['nan'] + [0] * 26 + ['Benign'])
            writer.writerow(header)
            writer.writerow(['malformed'])
        (self.data / (name + '.acquisition.json')).write_text(json.dumps({
            'file': name, 'source_url': runner.BASE + name, 'sha256': _sha(path),
            'bytes': path.stat().st_size, 'etag': 'etag', 'last_modified': 'date',
            'role': 'reserved final external evaluation, no outcomes inspected'}))

    def load_fake(self, path):
        variant = Path(path).name
        digest = _sha(Path(path) / 'bundle.joblib')
        return ({'threshold': 0.5, 'binary_pipeline': variant},
                {'variant': variant, 'bundle_sha256': digest, 'threshold': 0.5})

    def test_streams_collisions_and_accounts_outputs(self):
        output = self.root / 'out'
        with patch.object(runner, 'load_binary', side_effect=self.load_fake), patch.object(
                runner, 'attack_scores', side_effect=lambda model, matrix: np.array(matrix[:, 0])):
            runner.run_robustness(self.data, self.model, self.source, self.commitment, output, batch_size=1)
        result = json.loads((output / 'results.json').read_text())
        day = result['quality'][runner.FILES[0]]
        self.assertEqual(day['counts']['feature_group_matches_frozen'], 1)
        self.assertEqual(day['counts']['invalid_feature'], 1)
        self.assertEqual(day['counts']['repeated_header'], 1)
        self.assertEqual(day['counts']['malformed_width'], 1)
        self.assertEqual(result['results']['original']['pooled']['metrics']['tp'], 2)
        self.assertEqual(result['results']['original']['pooled']['metrics']['tn'], 2)
        with (output / 'exclusions.csv').open(newline='', encoding='utf-8') as stream:
            self.assertEqual(len(list(csv.DictReader(stream))), 6)
        with self.assertRaises(ValueError):
            runner.run_robustness(self.data, self.model, self.source, self.commitment, output)

    def test_unknown_label_blocks_all_scoring_and_cleans_stage(self):
        self.write_data(runner.FILES[1], unknown=True)
        self.write_commitment()
        output = self.root / 'out'
        with patch.object(runner, 'load_binary', side_effect=self.load_fake), patch.object(runner, 'attack_scores') as scorer:
            with self.assertRaisesRegex(ValueError, 'Unknown label'):
                runner.run_robustness(self.data, self.model, self.source, self.commitment, output)
            scorer.assert_not_called()
        self.assertFalse(output.exists())

    def test_file_tampering_fails_before_scoring(self):
        (self.data / runner.FILES[0]).write_text('changed')
        with patch.object(runner, 'attack_scores') as scorer:
            with self.assertRaisesRegex(ValueError, 'provenance'):
                runner.run_robustness(self.data, self.model, self.source, self.commitment, self.root / 'out')
            scorer.assert_not_called()

    def test_commitment_mismatch_blocks_preflight_and_scoring(self):
        record = json.loads(self.commitment.read_text())
        record['runner_sha256'] = '0' * 64
        self.commitment.write_text(json.dumps(record))
        with patch.object(runner, 'load_binary', side_effect=self.load_fake) as loader, patch.object(runner, 'attack_scores') as scorer:
            with self.assertRaisesRegex(ValueError, 'commitment mismatch'):
                runner.run_robustness(self.data, self.model, self.source, self.commitment, self.root / 'out')
            scorer.assert_not_called()
            loader.assert_not_called()
        self.assertFalse((self.root / 'out').exists())

    def test_dependency_mismatch_blocks_deserialization(self):
        record = json.loads(self.commitment.read_text())
        record['dependency_sha256']['attack_traffic/evaluate.py'] = '0' * 64
        self.commitment.write_text(json.dumps(record))
        with patch.object(runner, 'load_binary') as loader:
            with self.assertRaisesRegex(ValueError, 'commitment mismatch'):
                runner.run_robustness(self.data, self.model, self.source, self.commitment, self.root / 'out')
            loader.assert_not_called()

    def test_bundle_mismatch_blocks_deserialization(self):
        (self.model / 'original' / 'bundle.joblib').write_bytes(b'changed')
        with patch.object(runner, 'load_binary') as loader:
            with self.assertRaisesRegex(ValueError, 'commitment mismatch'):
                runner.run_robustness(self.data, self.model, self.source, self.commitment, self.root / 'out')
            loader.assert_not_called()


if __name__ == '__main__':
    unittest.main()
