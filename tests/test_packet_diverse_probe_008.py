from scripts.packet_diverse_probe_008 import compare_flags


def test_comparison_distinguishes_first_packet_from_full_flow_counts():
    flags = {'FIN': 0, 'SYN': 1, 'RST': 0, 'PSH': 0, 'ACK': 0, 'URG': 0, 'ECE': 0}
    result = compare_flags(flags, [0x02, 0x12])
    assert result['matches_first']['SYN'] and result['matches_first']['ACK']
    assert not result['matches_full']['SYN'] and not result['matches_full']['ACK']
    assert result['all_packets']['SYN'] == 2 and result['all_packets']['ACK'] == 1
