import importlib.util
from pathlib import Path


def test_threshold_keeps_tied_scores_together_and_respects_fpr():
    path = Path(__file__).resolve().parents[1] / 'scripts' / 'calibrate_experiment007.py'
    spec = importlib.util.spec_from_file_location('calibrate007', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result = module.choose([(0.9, 1, 3), (0.8, 1, 100), (0.1, 98, 0)], 100, 103)
    assert result['threshold'] == 0.9
    assert result['fp'] == 1 and result['tp'] == 3
    result = module.choose([(0.9, 2, 3), (0.1, 98, 0)], 100, 3)
    assert result['threshold'] > 0.9 and not result['useful']
