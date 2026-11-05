import importlib.util
from pathlib import Path


def test_assessment_metrics_and_weighted_score_distribution():
    path = Path(__file__).resolve().parents[1] / 'scripts' / 'assess_experiment007.py'
    spec = importlib.util.spec_from_file_location('assess007', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result = module.summarize(8, 1, 99, 2)
    assert result['recall'] == 0.8 and result['fpr'] == 0.01
    dist = module.distribution([(0.0, 50), (0.5, 40), (1.0, 10)])
    assert dist['zero_scores'] == 50
    assert dist['quantiles'] == {'0.5': 0.0, '0.9': 0.5, '0.99': 1.0}
