import json
import tempfile
import unittest
from pathlib import Path

from attack_traffic.freeze_binary import freeze_binary_models, load_binary
from attack_traffic.tune import run_weight_ablation
from test_feature_extract import make_feature_source


class BinaryFreezeTests(unittest.TestCase):
    def test_roundtrip_and_reference_tampering_rejected(self):
        scratch = Path(__file__).resolve().parent.parent / '.test-tmp'
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            root = Path(temporary)
            source = make_feature_source(root / 'fixture')['source']
            reference = run_weight_ablation(source, root / 'reference')
            selection_path = reference / 'selection.json'
            selection = json.loads(selection_path.read_text())
            selection.update(promoted_candidate='balanced_subsample', promotion_passed=True)
            selection_path.write_text(json.dumps(selection))
            output = freeze_binary_models(source, reference, root / 'output')
            provenance = json.loads((output / 'provenance.json').read_text())
            for variant in ('original', 'corrected'):
                bundle, metadata = load_binary(output / variant)
                self.assertEqual(bundle['variant'], variant)
                self.assertEqual(bundle['threshold'], metadata['threshold'])
                self.assertGreater(provenance['variants'][variant]['validation_rows_exact_before_and_after_reload'], 0)
            metadata_path = output / 'corrected' / 'metadata.json'
            original_metadata = json.loads(metadata_path.read_text())
            for field, value in (('threshold', float('nan')), ('feature_units', {}), ('feature_allowlist', ['unsafe'])):
                damaged = dict(original_metadata, **{field: value})
                metadata_path.write_text(json.dumps(damaged))
                with self.assertRaisesRegex(ValueError, 'feature or threshold'):
                    load_binary(output / 'corrected')
            metadata_path.write_text(json.dumps(original_metadata))
            with self.assertRaises(ValueError):
                freeze_binary_models(source, reference, output)
            model = output / 'original' / 'bundle.joblib'
            model.write_bytes(model.read_bytes() + b'tamper')
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                load_binary(output / 'original')
            metrics_path = reference / 'candidate_metrics.json'
            metrics = json.loads(metrics_path.read_text())
            metrics['candidates']['balanced_subsample']['variants']['original']['threshold_policy']['threshold'] += 1
            metrics_path.write_text(json.dumps(metrics))
            with self.assertRaisesRegex(ValueError, 'threshold policy'):
                freeze_binary_models(source, reference, root / 'bad')
            self.assertFalse((root / 'bad').exists())

    def test_loader_checks_environment_before_deserialization(self):
        scratch = Path(__file__).resolve().parent.parent / '.test-tmp'
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            directory = Path(temporary)
            (directory / 'metadata.json').write_text(json.dumps({'schema_version': 1, 'bundle_type': 'binary_random_forest_v1', 'environment': {}}))
            with self.assertRaisesRegex(ValueError, 'environment'):
                load_binary(directory)


if __name__ == '__main__':
    unittest.main()
