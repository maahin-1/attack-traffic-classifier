from scripts.experiment008_dev_compare import family_metrics, split_development


def test_deduplicates_by_baseline_and_blocks_training_groups_from_wednesday():
    rows = [
        {'date': '2017-07-03', 'member': 'm', 'record': 2, 'base': (1.0,), 'extra': (6,)},
        {'date': '2017-07-04', 'member': 't', 'record': 2, 'base': (1.0,), 'extra': (17,)},
        {'date': '2017-07-05', 'member': 'w', 'record': 2, 'base': (1.0,), 'extra': (0,)},
        {'date': '2017-07-05', 'member': 'w', 'record': 3, 'base': (2.0,), 'extra': (6,)},
        {'date': '2017-07-05', 'member': 'w', 'record': 4, 'base': (2.0,), 'extra': (17,)},
        {'date': '2017-07-06', 'member': 'h', 'record': 2, 'base': (3.0,), 'extra': (6,)},
    ]
    train, validation, counts = split_development(rows)
    assert [r['record'] for r in train] == [2]
    assert [r['record'] for r in validation] == [3]
    assert counts == {'train_input': 2, 'train_dropped': 1, 'validation_input': 3, 'validation_dropped': 2}


def test_family_recall_uses_attack_rows_and_inclusive_threshold():
    rows = [{'family': 'a'}, {'family': 'a'}, {'family': 'a'}, {'family': 'b'}]
    result = family_metrics(rows, [1, 1, 0, 1], [0.5, 0.1, 0.9, 0.2], 0.5)
    assert result == {'a': {'support': 2, 'detected': 1, 'recall': 0.5}, 'b': {'support': 1, 'detected': 0, 'recall': 0.0}}
