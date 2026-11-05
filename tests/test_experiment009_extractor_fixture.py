import io
from collections import Counter
from scripts.experiment009_extractor_spike import checksum, fixture, tcp_packet
from scripts.ton_iot_scanning1_probe_009 import packets


def test_synthetic_ethernet_and_cooked_packets_are_equivalent():
    left=list(packets(io.BytesIO(fixture(1)),Counter()))
    right=list(packets(io.BytesIO(fixture(113)),Counter()))
    assert left==right and len(left)==3
    assert left[0][1]==left[2][1]
    assert left[0][1][1:3]==left[1][1][3:5]
    assert left[0][0]==1700000000 and left[-1][0]==1700000001
    assert checksum(tcp_packet()[:20])==0
