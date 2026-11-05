from scripts.packet_stratified_probe_008 import CSV_FLAGS, flag_agreements


def test_agreements_reports_support_and_mismatches_without_assuming_mapping():
    a = dict.fromkeys(CSV_FLAGS, 0); a['ACK'] = 1
    b = dict.fromkeys(CSV_FLAGS, 0); b['URG'] = 1
    result = flag_agreements([{'csv_flags':a,'first_mask':2}, {'csv_flags':b,'first_mask':16}])
    assert result['ACK']['csv_positive'] == 1
    assert result['ACK']['agreement']['SYN'] == 2
    assert result['ACK']['agreement']['ACK'] == 0
    assert result['URG']['agreement']['ACK'] == 2
