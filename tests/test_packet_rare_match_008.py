import io
import struct

from scripts.packet_rare_match_008 import classify, epoch_us, records


def test_window_boundaries_and_clock_conversion():
    start = epoch_us('2018-11-03 16:46:50.527385')
    assert classify(start + 10800000000, start, 10) == 'inside'
    assert classify(start + 10800000010, start, 10) == 'inside'
    assert classify(start + 10799999999, start, 10) == 'before'
    assert classify(start + 10800000011, start, 10) == 'after'


def test_incomplete_packet_excluded():
    header = bytes.fromhex('d4c3b2a1') + struct.pack('<HHiIII', 2, 4, 0, 0, 65535, 1)
    data = header + struct.pack('<IIII', 1700000000, 1, 40, 40) + b'abc'
    assert list(records(io.BytesIO(data))) == [{'truncated_data_bytes': 3, 'expected': 40}]
