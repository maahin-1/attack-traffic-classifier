import io
import hashlib
import ipaddress
import json
import struct
import sys

import pytest

from scripts import packet_probe_008
from scripts.packet_probe_008 import scan_pcap, target_tuple


SRC = ipaddress.IPv4Address('192.0.2.1').packed
DST = ipaddress.IPv4Address('198.51.100.2').packed
TARGET = (SRC, 12345, DST, 443)


def ipv4_tcp(source, src_port, destination, dst_port, flags, fragment=0):
    ip = bytearray(20)
    ip[0] = 0x45
    ip[2:4] = (40).to_bytes(2, 'big')
    ip[6:8] = fragment.to_bytes(2, 'big')
    ip[9] = 6
    ip[12:16], ip[16:20] = source, destination
    tcp = bytearray(20)
    tcp[0:2], tcp[2:4] = src_port.to_bytes(2, 'big'), dst_port.to_bytes(2, 'big')
    tcp[12], tcp[13] = 0x50, flags
    return bytes(ip + tcp)


def pcap(endian, magic, resolution_fraction, linktype, frames):
    content = bytearray(magic + struct.pack(endian + 'HHiIII', 2, 4, 0, 0, 65535, linktype))
    for seq, frame in enumerate(frames):
        content.extend(struct.pack(endian + 'IIII', 1700000000 + seq, resolution_fraction, len(frame), len(frame)))
        content.extend(frame)
    return bytes(content)


@pytest.mark.parametrize(('endian', 'magic', 'fraction', 'suffix'), [
    ('<', b'\xd4\xc3\xb2\xa1', 123, '.000123000Z'),
    ('>', b'\xa1\xb2\xc3\xd4', 123, '.000123000Z'),
    ('<', b'\x4d\x3c\xb2\xa1', 123, '.000000123Z'),
    ('>', b'\xa1\xb2\x3c\x4d', 123, '.000000123Z'),
])
def test_scans_vlan_tcp_in_both_directions_without_exposing_tuple(endian, magic, fraction, suffix):
    ethernet_vlan = b'\x00' * 12 + b'\x81\x00\x00\x01\x08\x00'
    frames = [ethernet_vlan + ipv4_tcp(SRC, 12345, DST, 443, 0x02),
              ethernet_vlan + ipv4_tcp(DST, 443, SRC, 12345, 0x12),
              ethernet_vlan + ipv4_tcp(SRC, 12345, DST, 80, 0x10)]
    result = scan_pcap(io.BytesIO(pcap(endian, magic, fraction, 1, frames)), TARGET)
    assert result['packets_scanned'] == 3 and result['matching_tuple_packets'] == 2
    assert result['matching_directions'] == {'forward': 1, 'reverse': 1}
    assert result['flag_counts'] == {'SYN': 2, 'ACK': 1}
    assert result['first_matching_packet_utc'].endswith(suffix)
    assert '192.0.2.1' not in json.dumps(result)


def test_raw_ipv4_and_fragment_handling():
    frames = [ipv4_tcp(SRC, 12345, DST, 443, 0x10), ipv4_tcp(SRC, 12345, DST, 443, 0x02, fragment=1)]
    result = scan_pcap(io.BytesIO(pcap('<', b'\xd4\xc3\xb2\xa1', 0, 101, frames)), TARGET)
    assert result['matching_tuple_packets'] == 1 and result['flag_counts'] == {'ACK': 1}


def test_rejects_truncated_or_unsupported_capture():
    frame = ipv4_tcp(SRC, 12345, DST, 443, 0x02)
    raw = pcap('<', b'\xd4\xc3\xb2\xa1', 0, 101, [frame])
    with pytest.raises(ValueError, match='Truncated PCAP packet body'):
        scan_pcap(io.BytesIO(raw[:-1]), TARGET)
    with pytest.raises(ValueError, match='PCAPNG'):
        scan_pcap(io.BytesIO(b'\x0a\x0d\x0d\x0a'), TARGET)
    unsupported = pcap('<', b'\xd4\xc3\xb2\xa1', 0, 113, [])
    with pytest.raises(ValueError, match='link type'):
        scan_pcap(io.BytesIO(unsupported), TARGET)


def test_target_validation():
    doc = {'status': 'ready_for_pcap', 'target': {'fields': {'Source IP': '192.0.2.1', 'Source Port': '12345',
        'Destination IP': '198.51.100.2', 'Destination Port': '443', 'Protocol': '6', 'Timestamp': '2018-11-03 11:29:17'}}}
    target, stamp = target_tuple(doc)
    assert target == TARGET and stamp == '2018-11-03 11:29:17'
    doc['target']['fields']['Protocol'] = '17'
    with pytest.raises(ValueError, match='TCP'):
        target_tuple(doc)


def test_cli_writes_redacted_report_without_changing_capture(tmp_path, monkeypatch):
    target_dir = tmp_path / 'prepared'
    target_dir.mkdir()
    source_protocol = target_dir / 'protocol.json'
    source_protocol.write_text('{}', encoding='utf-8')
    target = {'status': 'ready_for_pcap', 'protocol_sha256': hashlib.sha256(source_protocol.read_bytes()).hexdigest(),
              'target': {'fields': {'Source IP': '192.0.2.1', 'Source Port': '12345', 'Destination IP': '198.51.100.2',
                                    'Destination Port': '443', 'Protocol': '6', 'Timestamp': '2018-11-03 11:29:17'}}}
    target_path = target_dir / 'targets.json'
    target_path.write_text(json.dumps(target), encoding='utf-8')
    frame = ipv4_tcp(SRC, 12345, DST, 443, 0x02)
    original = pcap('<', b'\xd4\xc3\xb2\xa1', 0, 101, [frame])
    capture = tmp_path / 'fixture.pcap'
    capture.write_bytes(original)
    out = tmp_path / 'artifacts' / 'report'
    monkeypatch.setattr(packet_probe_008, 'ROOT', tmp_path)
    monkeypatch.setattr(packet_probe_008, 'TARGET', target_path)
    monkeypatch.setattr(packet_probe_008, 'OUT', out)
    monkeypatch.setattr(sys, 'argv', ['packet_probe_008.py', str(capture)])
    packet_probe_008.main()
    report = json.loads((out / 'report.json').read_text())
    assert report['status'] == 'complete' and report['matching_tuple_packets'] == 1
    assert report['csv_clock_unaligned'] == '2018-11-03 11:29:17'
    assert '192.0.2.1' not in (out / 'report.json').read_text()
    assert capture.read_bytes() == original
