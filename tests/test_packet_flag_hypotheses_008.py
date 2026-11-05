from scripts.packet_flag_hypotheses_008 import CSV_FLAGS, correlations


def test_hypothesis_counts_positive_agreement_without_assuming_mapping():
    first = dict.fromkeys(CSV_FLAGS, 0)
    first['ACK'] = 1
    second = dict.fromkeys(CSV_FLAGS, 0)
    second['URG'] = 1
    result = correlations([{'csv':first, 'first_flags':2}, {'csv':second, 'first_flags':16}])
    assert result['ACK']['positive_rows'] == 1
    assert result['ACK']['first_packet_agreements']['SYN'] == 2
    assert result['ACK']['first_packet_agreements']['ACK'] == 0
    assert result['URG']['first_packet_agreements']['ACK'] == 2
