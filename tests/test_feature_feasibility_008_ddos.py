import sqlite3

from scripts.feature_feasibility_008_ddos import group_summary


def test_group_summary_counts_conflicts_and_minority_rows():
    db = sqlite3.connect(':memory:')
    db.execute('CREATE TABLE groups (mode TEXT, digest BLOB, benign INTEGER, attack INTEGER)')
    db.executemany('INSERT INTO groups VALUES (?,?,?,?)', [
        ('base', b'a', 3, 8), ('base', b'b', 0, 5), ('flags', b'a', 3, 0), ('flags', b'b', 0, 8),
    ])
    base = group_summary(db, 'base')
    flags = group_summary(db, 'flags')
    assert base == {'groups': 2, 'conflicting_groups': 1, 'rows_in_conflicting_groups': 11, 'minority_label_rows_lower_bound': 3}
    assert flags['conflicting_groups'] == 0 and flags['rows_in_conflicting_groups'] == 0
