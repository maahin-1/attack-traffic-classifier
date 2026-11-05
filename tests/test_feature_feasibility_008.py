from scripts.feature_feasibility_008 import collision_summary


def test_added_flags_separate_labels_without_changing_sample():
    records = [
        {'features': (1.0,), 'extra': (6, 0), 'label': 0},
        {'features': (1.0,), 'extra': (6, 1), 'label': 1},
        {'features': (2.0,), 'extra': (17, 0), 'label': 1},
    ]
    base = collision_summary(records, 'base')
    protocol = collision_summary(records, 'protocol')
    flags = collision_summary(records, 'flags')
    assert base['conflicting_groups'] == 1 and base['minority_label_rows_lower_bound'] == 1
    assert protocol['conflicting_groups'] == 1
    assert flags['conflicting_groups'] == 0 and flags['groups'] == 3
