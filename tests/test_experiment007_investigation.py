from collections import Counter

from scripts.investigate_experiment007 import update_context


def test_context_keeps_each_label_and_time_range_separate():
    group = {'labels': Counter(), 'members': Counter(), 'protocols': Counter(),
             'destination_ports': Counter(), 'by_label': {}}
    update_context(group, 'UDP', 'a.csv', '2018-11-03 11:00:02', '17', '53', 5)
    update_context(group, 'UDP', 'a.csv', '2018-11-03 11:00:01', '17', '53', 6)
    update_context(group, 'BENIGN', 'b.csv', '2018-11-03 10:00:00', '6', '80', 7)
    assert group['labels'] == {'UDP': 2, 'BENIGN': 1}
    assert group['by_label']['UDP']['first_timestamp'] == '2018-11-03 11:00:01'
    assert group['by_label']['UDP']['last_timestamp'] == '2018-11-03 11:00:02'
    assert group['by_label']['BENIGN']['example']['member'] == 'b.csv'
    assert group['destination_ports']['53'] == 2
