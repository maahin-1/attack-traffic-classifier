"""Stream a classic PCAP and inspect packets matching the prepared CSV tuple.

This tool does not align clocks, reconstruct flows, or decide label correctness.
Only aggregate results and bounded packet examples are written to the report.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import struct
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/experiment-008-packet-probe/targets.json'
OUT = ROOT / 'artifacts/experiment-008-pcap-inspection'
MAX_CAPTURE = 16 * 1024 * 1024
MAGICS = {
    b'\xd4\xc3\xb2\xa1': ('<', 1_000_000, 'microsecond'),
    b'\xa1\xb2\xc3\xd4': ('>', 1_000_000, 'microsecond'),
    b'\x4d\x3c\xb2\xa1': ('<', 1_000_000_000, 'nanosecond'),
    b'\xa1\xb2\x3c\x4d': ('>', 1_000_000_000, 'nanosecond'),
}
FLAGS = (('FIN', 0x01), ('SYN', 0x02), ('RST', 0x04), ('PSH', 0x08),
         ('ACK', 0x10), ('URG', 0x20), ('ECE', 0x40), ('CWR', 0x80))


def file_hash(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def read_exact(stream, count, description):
    data = stream.read(count)
    if len(data) != count:
        raise ValueError(f'Truncated {description}')
    return data


def target_tuple(document):
    if document.get('status') != 'ready_for_pcap':
        raise ValueError('Packet probe target is not ready')
    try:
        fields = document['target']['fields']
        source = ipaddress.IPv4Address(fields['Source IP']).packed
        destination = ipaddress.IPv4Address(fields['Destination IP']).packed
        source_port, destination_port = int(fields['Source Port']), int(fields['Destination Port'])
        protocol = int(fields['Protocol'])
        stamp = fields['Timestamp']
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError('Invalid IPv4 target fields') from exc
    if protocol != 6 or not (0 <= source_port <= 65535 and 0 <= destination_port <= 65535):
        raise ValueError('Target must contain TCP and valid ports')
    if not isinstance(stamp, str) or not stamp.strip():
        raise ValueError('Missing unaligned source-clock timestamp')
    return (source, source_port, destination, destination_port), stamp


def tcp_packet(frame, linktype):
    """Return (source, source-port, destination, destination-port, flags), or None."""
    if linktype == 1:
        if len(frame) < 14:
            return None
        ether_type = int.from_bytes(frame[12:14], 'big')
        offset = 14
        for _ in range(4):
            if ether_type not in (0x8100, 0x88a8, 0x9100):
                break
            if len(frame) < offset + 4:
                return None
            ether_type = int.from_bytes(frame[offset + 2:offset + 4], 'big')
            offset += 4
        if ether_type != 0x0800:
            return None
    elif linktype == 101:
        offset = 0
    else:
        raise ValueError(f'Unsupported PCAP link type: {linktype}')
    if len(frame) < offset + 20 or frame[offset] >> 4 != 4:
        return None
    ip_len = (frame[offset] & 15) * 4
    if ip_len < 20 or len(frame) < offset + ip_len:
        return None
    total_len = int.from_bytes(frame[offset + 2:offset + 4], 'big')
    fragment_offset = int.from_bytes(frame[offset + 6:offset + 8], 'big') & 0x1fff
    if frame[offset + 9] != 6 or fragment_offset or total_len < ip_len + 20:
        return None
    tcp = offset + ip_len
    if len(frame) < tcp + 20:
        return None
    tcp_len = (frame[tcp + 12] >> 4) * 4
    if tcp_len < 20 or total_len < ip_len + tcp_len or len(frame) < tcp + tcp_len:
        return None
    return (frame[offset + 12:offset + 16], int.from_bytes(frame[tcp:tcp + 2], 'big'),
            frame[offset + 16:offset + 20], int.from_bytes(frame[tcp + 2:tcp + 4], 'big'), frame[tcp + 13])


def iso_utc(seconds, fractional_ns):
    try:
        base = datetime.fromtimestamp(seconds, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')
    except (OverflowError, OSError, ValueError) as exc:
        raise ValueError('PCAP timestamp is out of range') from exc
    return f'{base}.{fractional_ns:09d}Z'


def scan_pcap(stream, target, progress=None, examples_limit=20):
    magic = read_exact(stream, 4, 'PCAP magic')
    if magic == b'\x0a\x0d\x0d\x0a':
        raise ValueError('PCAPNG is not supported; provide a classic PCAP')
    if magic not in MAGICS:
        raise ValueError('Unsupported format; expected an uncompressed classic PCAP')
    endian, resolution, precision = MAGICS[magic]
    major, minor, _zone, _sigfigs, snaplen, linktype = struct.unpack(endian + 'HHiIII', read_exact(stream, 20, 'PCAP header'))
    if (major, minor) != (2, 4) or not 0 < snaplen <= MAX_CAPTURE:
        raise ValueError('Unsupported PCAP version or snapshot length')
    if linktype not in (1, 101):
        raise ValueError(f'Unsupported PCAP link type: {linktype}')
    source, source_port, destination, destination_port = target
    forward = (source, source_port, destination, destination_port)
    reverse = (destination, destination_port, source, source_port)
    packet_count = matched = 0
    directions = Counter(); flag_counts = Counter(); combinations = Counter()
    first = last = None; examples = []
    while True:
        header = stream.read(16)
        if not header:
            break
        if len(header) != 16:
            raise ValueError('Truncated PCAP packet header')
        sec, fraction, captured, original = struct.unpack(endian + 'IIII', header)
        if fraction >= resolution or captured > snaplen or captured > original or captured > MAX_CAPTURE:
            raise ValueError('Invalid PCAP packet timestamp or length')
        frame = read_exact(stream, captured, 'PCAP packet body')
        packet_count += 1
        packet = tcp_packet(frame, linktype)
        if packet is not None:
            key, mask = packet[:4], packet[4]
            direction = 'forward' if key == forward else 'reverse' if key == reverse else None
            if direction:
                matched += 1
                nanos = fraction * (1_000_000_000 // resolution)
                stamp = (sec, nanos)
                first = stamp if first is None or stamp < first else first
                last = stamp if last is None or stamp > last else last
                names = [name for name, bit in FLAGS if mask & bit]
                directions[direction] += 1
                flag_counts.update(names)
                combinations['|'.join(names) if names else 'NONE'] += 1
                if len(examples) < examples_limit:
                    examples.append({'timestamp_utc': iso_utc(sec, nanos), 'direction': direction, 'flags': names})
        if progress and packet_count % 1_000_000 == 0:
            progress(packet_count, matched)
    return {'format': 'classic_pcap', 'timestamp_precision': precision, 'link_type': linktype,
            'snapshot_length': snaplen, 'packets_scanned': packet_count, 'matching_tuple_packets': matched,
            'matching_directions': dict(directions), 'flag_counts': dict(flag_counts),
            'flag_combinations': dict(combinations),
            'first_matching_packet_utc': iso_utc(*first) if first else None,
            'last_matching_packet_utc': iso_utc(*last) if last else None,
            'examples_first_in_file_order': examples}


def write_json(path, obj):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(obj, sort_keys=True, indent=2, allow_nan=False) + '\n', encoding='utf-8')
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pcap', type=Path, help='Path to the user-provided uncompressed classic PCAP')
    parser.add_argument('--output', type=Path, default=OUT, help='New output directory under the project artifacts folder')
    args = parser.parse_args()
    capture = args.pcap.resolve(strict=True)
    out = args.output.resolve()
    artifacts = (ROOT / 'artifacts').resolve()
    if out == artifacts or not out.is_relative_to(artifacts):
        raise ValueError('Output must be a new directory under the project artifacts folder')
    target_bytes = TARGET.read_bytes()
    target_hash = hashlib.sha256(target_bytes).hexdigest()
    target_doc = json.loads(target_bytes)
    target, csv_clock = target_tuple(target_doc)
    linked_protocol = TARGET.with_name('protocol.json')
    if file_hash(linked_protocol) != target_doc.get('protocol_sha256'):
        raise ValueError('Prepared target protocol hash mismatch')
    source_hash = file_hash(capture)
    out.mkdir(parents=True, exist_ok=False)
    policy = {'source_path': str(capture), 'source_bytes': capture.stat().st_size, 'source_sha256': source_hash,
              'target_sha256': target_hash, 'target_protocol_sha256': file_hash(linked_protocol),
              'parser_sha256': file_hash(Path(__file__)), 'csv_clock_unaligned': csv_clock,
              'clock_policy': 'PCAP timestamps shown as UTC; CSV clock is not aligned or shifted',
              'match_policy': 'exact IPv4 TCP 5-tuple in either direction; full source scan',
              'limits': 'Ethernet with up to four VLAN tags or raw IPv4; classic PCAP only; packet match is not flow reconstruction'}
    write_json(out / 'protocol.json', policy)
    try:
        with capture.open('rb') as stream:
            result = scan_pcap(stream, target, lambda packets, matches: write_json(out / 'progress.json',
                        {'status': 'running', 'packets_scanned': packets, 'matching_tuple_packets': matches}))
        if file_hash(capture) != source_hash or file_hash(TARGET) != target_hash or file_hash(linked_protocol) != policy['target_protocol_sha256'] or file_hash(Path(__file__)) != policy['parser_sha256']:
            raise ValueError('A source or parser changed during packet inspection')
        result.update({'status': 'complete', 'protocol_sha256': file_hash(out / 'protocol.json'),
                       'csv_clock_unaligned': csv_clock, 'limitations': 'Tuple matches do not prove flow membership, time alignment, source producer version, or label correctness.'})
        write_json(out / 'report.json', result)
        write_json(out / 'progress.json', {'status': 'complete', 'packets_scanned': result['packets_scanned'],
                                          'matching_tuple_packets': result['matching_tuple_packets']})
        print(f"Scanned {result['packets_scanned']} packets; found {result['matching_tuple_packets']} tuple matches.")
    except BaseException as exc:
        write_json(out / 'progress.json', {'status': 'failed', 'error': str(exc)})
        raise


if __name__ == '__main__':
    main()
