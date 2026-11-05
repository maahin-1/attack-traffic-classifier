import unittest
import csv
import json
import hashlib
import tempfile
from pathlib import Path

from attack_traffic.support_ablation import _select, run_support_ablation
from attack_traffic.tune import SOURCE_FILES
from test_feature_extract import make_feature_source


def outcome(recall, fpr=0.005, status='ok'):
    return {'status': status, 'validation': {'recall': recall, 'fpr': fpr}, 'threshold_policy': {'fpr_target': 0.01}}


class SelectionTests(unittest.TestCase):
    def candidates(self, a, b):
        return {'baseline': {'variants': {'original': outcome(a[0]), 'corrected': outcome(a[1])}}, 'expanded': {'variants': {'original': outcome(b[0]), 'corrected': outcome(b[1])}}}

    def test_advances_only_with_joint_improvement_and_no_regression(self):
        self.assertTrue(_select(self.candidates((0.1, 0.2), (0.1, 0.3)))['promotion_passed'])
        result = _select(self.candidates((0.1, 0.2), (0.2, 0.19)))
        self.assertEqual(result['best_candidate'], 'expanded')
        self.assertEqual(result['promoted_candidate'], 'baseline')

    def test_prefers_baseline_on_ties_and_rejects_fpr_violation(self):
        self.assertEqual(_select(self.candidates((0.1, 0.2), (0.1, 0.2)))['best_candidate'], 'baseline')
        candidates = self.candidates((0.1, 0.2), (0.5, 0.5))
        candidates['expanded']['variants']['corrected']['validation']['fpr'] = 0.011
        self.assertEqual(_select(candidates)['promoted_candidate'], 'baseline')


class RunnerTests(unittest.TestCase):
    candidates = SelectionTests.candidates

    def test_empty_supplement_preserves_validation_scores(self):
        scratch = Path(__file__).resolve().parent.parent / '.test-tmp'
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as tmp:
            root = Path(tmp)
            fixture = make_feature_source(root / 'fixture')
            source = fixture['source']
            config = json.loads((source / 'config.json').read_text())
            extra = root / 'extra'
            extra.mkdir()
            with (extra / 'supplement.csv').open('w', newline='', encoding='utf-8') as f:
                csv.writer(f).writerow(['variant', 'origin_member', 'origin_record', 'source_label', 'family', 'binary_label', 'duplicate_group_id', *config['feature_allowlist']])
            (extra / 'exclusions.csv').write_text('variant,origin_member,origin_record,reason\n', encoding='utf-8')
            sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
            summary = {'schema_version': 1, 'status': 'ok', 'source_files': {n: sha(source / n) for n in SOURCE_FILES}, 'archive_sha256': {d['variant']: d['preparation']['archive_sha256'] for d in config['datasets']}, 'supplement_sha256': sha(extra / 'supplement.csv'), 'exclusions_sha256': sha(extra / 'exclusions.csv'), 'counts': {d['variant']: {} for d in config['datasets']}}
            (extra / 'summary.json').write_text(json.dumps(summary), encoding='utf-8')
            result = run_support_ablation(source, extra, root / 'result')
            with (result / 'validation_predictions.csv').open(newline='', encoding='utf-8') as f:
                rows = list(csv.DictReader(f))
            a = [(r['variant'], r['record_id'], r['attack_score'], r['threshold']) for r in rows if r['candidate'] == 'baseline']
            b = [(r['variant'], r['record_id'], r['attack_score'], r['threshold']) for r in rows if r['candidate'] == 'expanded']
            self.assertTrue(a)
            self.assertEqual(a, b)
            self.assertEqual(json.loads((result / 'selection.json').read_text())['promoted_candidate'], 'baseline')

    def test_failed_or_missing_variant_never_advances(self):
        candidates = self.candidates((0.1, 0.2), (0.5, 0.5))
        candidates['expanded']['variants']['corrected'] = {'status': 'failed'}
        self.assertEqual(_select(candidates)['promoted_candidate'], 'baseline')

    def test_failed_baseline_has_no_decision(self):
        candidates = self.candidates((0.1, 0.2), (0.5, 0.5))
        candidates['baseline']['variants']['corrected'] = {'status': 'failed'}
        decision = _select(candidates)
        self.assertIsNone(decision['promoted_candidate'])
        self.assertEqual(decision['status'], 'failed_reference')
        candidates = self.candidates((0.1, 0.2), (0.5, 0.5))
        del candidates['expanded']['variants']['corrected']
        self.assertEqual(_select(candidates)['promoted_candidate'], 'baseline')


if __name__ == '__main__':
    unittest.main()
