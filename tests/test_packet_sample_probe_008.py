import struct

from scripts.packet_sample_probe_008 import tcp_tuple_and_flags


def frame(fragment=0, flags=2):
    ip = bytearray(20)
    ip[0], ip[9] = 0x45, 6
    ip[2:4] = (40).to_bytes(2, 'big')
    ip[6:8] = fragment.to_bytes(2, 'big')
    ip[12:16], ip[16:20] = b'\xc0\x00\x02\x01', b'\xc6\x33\x64\x02'
    tcp = bytearray(20)
    struct.pack_into('!HH', tcp, 0, 1234, 80)
    tcp[12], tcp[13] = 0x50, flags
    return b'\0'*12 + b'\x81\x00\x00\x01\x08\x00' + bytes(ip + tcp)


def test_independent_decoder_reads_syn_and_vlan():
    key, flags = tcp_tuple_and_flags(frame())
    assert (key[1], key[3], flags) == (1234, 80, 2)


def test_noninitial_fragment_and_truncated_tcp_are_not_treated_as_packets():
    assert tcp_tuple_and_flags(frame(fragment=1)) is None
    assert tcp_tuple_and_flags(frame()[:-1]) is None
