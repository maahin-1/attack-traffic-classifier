import importlib.util
import json
from pathlib import Path


def test_audit_counts_cross_day_and_conflicting_groups(tmp_path, monkeypatch):
    path = Path(__file__).resolve().parents[1] / 'scripts' / 'audit_experiment007.py'
    spec = importlib.util.spec_from_file_location('audit007', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, 'OUT', tmp_path / 'audit')
    def records(_path, role):
        yield {'features': [1.0] * 27, 'label': 0, 'source_label': 'BENIGN'}
        if role == 'assessment':
            yield {'features': [1.0] * 27, 'label': 1, 'source_label': 'UDP'}
        else:
            yield {'error': 'nonfinite_feature', 'source_label': 'UDP'}
    monkeypatch.setattr(module, 'iter_pinned_rows', records)
    module.main()
    report = json.loads((module.OUT / 'report.json').read_text())
    assert report['status'] == 'complete'
    assert report['roles']['calibration']['errors'] == {'nonfinite_feature': 1}
    assert report['collisions']['valid_rows'] == 3
    assert report['collisions']['cross_day_groups'] == 1
    assert report['collisions']['binary_conflict_groups'] == 1
    assert report['collisions']['rows_after_first'] == 2
