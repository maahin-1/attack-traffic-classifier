import json
import struct
import subprocess
import sys

import pytest

from scripts.experiment009_pcap_preflight import Rejection, inspect_pcap


def frame(linktype=1, protocol=17, payload=b'test', fragment=0, ether_type=0x0800):
    if protocol == 17:
        transport = struct.pack('!HHHH', 12345, 53, 8 + len(payload), 0) + payload
    else:
        transport = struct.pack('!HHIIHHHH', 12345, 443, 1, 0, 5 << 12, 0, 0, 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(transport), 0, fragment,
                     64, protocol, 0, b'\xc0\x00\x02\x01', b'\xc6\x33\x64\x02') + transport
    if linktype == 1:
        link = bytes.fromhex('020000000002020000000001') + struct.pack('!H', ether_type)
    else:
        link = struct.pack('!HHH8sH', 0, 1, 6, b'\x02\0\0\0\0\x01\0\0', ether_type)
    return link + ip


def pcap(packets, linktype=1, *, endian='<', nano=False):
    magic = {('<', False): b'\xd4\xc3\xb2\xa1', ('>', False): b'\xa1\xb2\xc3\xd4',
             ('<', True): b'\x4d\x3c\xb2\xa1', ('>', True): b'\xa1\xb2\x3c\x4d'}[(endian, nano)]
    data = bytearray(magic + struct.pack(endian + 'HHIIII', 2, 4, 0, 0, 65535, linktype))
    for sec, fraction, packet in packets:
        data.extend(struct.pack(endian + 'IIII', sec, fraction, len(packet), len(packet)))
        data.extend(packet)
    return bytes(data)


def reject(tmp_path, data, reason, packet_index=None):
    path = tmp_path / 'test.pcap'
    path.write_bytes(data)
    with pytest.raises(Rejection) as caught:
        inspect_pcap(path)
    assert (caught.value.reason, caught.value.packet_index) == (reason, packet_index)


@pytest.mark.parametrize('linktype', [1, 113])
@pytest.mark.parametrize('endian,nano', [('<', False), ('>', False), ('<', True), ('>', True)])
def test_accepts_ordered_complete_tcp_udp_and_equal_timestamps(tmp_path, linktype, endian, nano):
    packets = [(10, 0, frame(linktype)), (10, 0, frame(linktype, protocol=6)),
               (10, 1, frame(linktype))]
    path = tmp_path / 'test.pcap'
    path.write_bytes(pcap(packets, linktype, endian=endian, nano=nano))
    assert inspect_pcap(path) == {'accepted': True, 'packet_count': 3, 'linktype': linktype}


def test_rejects_timestamp_decrease_across_flows(tmp_path):
    reject(tmp_path, pcap([(10, 3, frame()), (10, 2, frame(protocol=6))]), 'timestamp_decrease', 2)


@pytest.mark.parametrize('fragment', [0x2000, 0x0001, 0x2001])
def test_rejects_first_and_later_ipv4_fragments(tmp_path, fragment):
    reject(tmp_path, pcap([(10, 0, frame(fragment=fragment))]), 'ipv4_fragment', 1)


def test_allows_unfragmented_dont_fragment_flag(tmp_path):
    path = tmp_path / 'test.pcap'
    path.write_bytes(pcap([(10, 0, frame(fragment=0x4000))]))
    assert inspect_pcap(path)['accepted']


def test_rejects_incomplete_or_malformed_pcap(tmp_path):
    data = pcap([(10, 0, frame())])
    reject(tmp_path, data[:10], 'truncated_pcap_header')
    reject(tmp_path, data[:30], 'truncated_record_header', 1)
    reject(tmp_path, data[:-1], 'truncated_record_data', 1)
    reject(tmp_path, pcap([]), 'empty_capture')
    reject(tmp_path, b'\x0a\x0d\x0d\x0a' + b'\0' * 20, 'unsupported_pcap_format')
    damaged = bytearray(data)
    struct.pack_into('<I', damaged, 36, len(frame()) + 1)
    reject(tmp_path, damaged, 'incomplete_capture', 1)
    reject(tmp_path, pcap([(10, 1_000_000, frame())]), 'invalid_timestamp', 1)


def test_rejects_unsupported_and_malformed_network_frames(tmp_path):
    reject(tmp_path, pcap([(10, 0, b'\0' * 10)]), 'truncated_link_header', 1)
    reject(tmp_path, pcap([(10, 0, frame(ether_type=0x8100))]), 'unsupported_network_protocol', 1)
    reject(tmp_path, pcap([(10, 0, frame(protocol=1))]), 'unsupported_transport_protocol', 1)
    malformed = bytearray(frame())
    malformed[14 + 2:14 + 4] = b'\xff\xff'
    reject(tmp_path, pcap([(10, 0, malformed)]), 'invalid_ipv4_length', 1)
    malformed = bytearray(frame())
    malformed[14 + 20 + 4:14 + 20 + 6] = b'\0\x09'
    reject(tmp_path, pcap([(10, 0, malformed)]), 'invalid_udp_length', 1)
    malformed = bytearray(frame(protocol=6))
    malformed[14 + 20 + 12] = 0x10
    reject(tmp_path, pcap([(10, 0, malformed)]), 'invalid_tcp_header', 1)
    reject(tmp_path, pcap([(10, 0, frame())], linktype=101), 'unsupported_linktype')


def test_cli_rejects_and_returns_machine_readable_reason(tmp_path):
    path = tmp_path / 'fragment.pcap'
    path.write_bytes(pcap([(10, 0, frame(fragment=0x2000))]))
    result = subprocess.run([sys.executable, '-m', 'scripts.experiment009_pcap_preflight', str(path)],
                            capture_output=True, text=True, check=False)
    assert result.returncode == 2
    assert json.loads(result.stdout) == {'accepted': False, 'reason': 'ipv4_fragment', 'packet_index': 1}
