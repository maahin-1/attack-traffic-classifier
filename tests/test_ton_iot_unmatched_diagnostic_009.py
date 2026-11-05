from scripts.ton_iot_unmatched_diagnostic_009 import add_window, partition


def test_time_windows_are_disjoint_and_keep_tuple_only_distinct():
    entries=[(100,0),(101,1),(105,2),(160,3),(161,4),(200,5)]
    found={n:set() for n in (0,1,5,60)}
    add_window(entries,100,found)
    result=partition(range(7),found,{0,1,2,3,4,5})
    assert result=={'same_second':1,'within_1s_only':1,'within_5s_only':1,
                    'within_60s_only':1,'tuple_only_outside_60s':2,'tuple_not_seen':1}


def test_overlapping_packet_windows_count_each_key_once():
    found={n:set() for n in (0,1,5,60)}
    add_window([(10,0)],9,found); add_window([(10,0)],10,found)
    assert partition([0],found,{0})['same_second']==1
