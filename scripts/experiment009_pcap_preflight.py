"""Conservative, streaming classic-PCAP preflight; does not extract flows."""
import argparse
import json
import struct
import sys
from pathlib import Path


MAX_FRAME = 16 * 1024 * 1024
MAGIC = {
    b'\xd4\xc3\xb2\xa1': ('<', 1_000),
    b'\xa1\xb2\xc3\xd4': ('>', 1_000),
    b'\x4d\x3c\xb2\xa1': ('<', 1),
    b'\xa1\xb2\x3c\x4d': ('>', 1),
}


class Rejection(Exception):
    def __init__(self, reason, packet_index=None):
        self.reason = reason
        self.packet_index = packet_index
        super().__init__(reason)


def validate_packet(frame, linktype, index):
    header_len = 14 if linktype == 1 else 16
    if len(frame) < header_len:
        raise Rejection('truncated_link_header', index)
    ether_type = int.from_bytes(frame[12:14] if linktype == 1 else frame[14:16], 'big')
    if ether_type != 0x0800:
        raise Rejection('unsupported_network_protocol', index)
    ip = frame[header_len:]
    if len(ip) < 20 or ip[0] >> 4 != 4:
        raise Rejection('invalid_ipv4_header', index)
    ihl = (ip[0] & 0x0f) * 4
    if ihl < 20 or len(ip) < ihl:
        raise Rejection('invalid_ipv4_header', index)
    ip_len = int.from_bytes(ip[2:4], 'big')
    if ip_len < ihl or ip_len > len(ip):
        raise Rejection('invalid_ipv4_length', index)
    fragment_field = int.from_bytes(ip[6:8], 'big')
    if fragment_field & 0x8000:
        raise Rejection('invalid_ipv4_flags', index)
    if fragment_field & 0x3fff:
        raise Rejection('ipv4_fragment', index)
    transport = ip[ihl:ip_len]
    if ip[9] == 6:
        if len(transport) < 20:
            raise Rejection('invalid_tcp_header', index)
        tcp_len = (transport[12] >> 4) * 4
        if tcp_len < 20 or tcp_len > len(transport):
            raise Rejection('invalid_tcp_header', index)
    elif ip[9] == 17:
        if len(transport) < 8 or int.from_bytes(transport[4:6], 'big') != len(transport):
            raise Rejection('invalid_udp_length', index)
    else:
        raise Rejection('unsupported_transport_protocol', index)


def inspect_pcap(path):
    """Read every record; raise Rejection at the first unaccepted condition."""
    count = 0
    with Path(path).open('rb') as stream:
        header = stream.read(24)
        if len(header) != 24:
            raise Rejection('truncated_pcap_header')
        if header[:4] not in MAGIC:
            raise Rejection('unsupported_pcap_format')
        endian, scale = MAGIC[header[:4]]
        major, minor, _zone, _sigfigs, snaplen, linktype = struct.unpack(endian + 'HHIIII', header[4:])
        if (major, minor) != (2, 4) or snaplen == 0:
            raise Rejection('invalid_pcap_header')
        if linktype not in (1, 113):
            raise Rejection('unsupported_linktype')
        previous = None
        while True:
            record = stream.read(16)
            if not record:
                break
            index = count + 1
            if len(record) != 16:
                raise Rejection('truncated_record_header', index)
            sec, fraction, captured, original = struct.unpack(endian + 'IIII', record)
            if fraction >= 1_000_000_000 // scale:
                raise Rejection('invalid_timestamp', index)
            timestamp_ns = sec * 1_000_000_000 + fraction * scale
            if previous is not None and timestamp_ns < previous:
                raise Rejection('timestamp_decrease', index)
            if captured > MAX_FRAME or captured > snaplen:
                raise Rejection('invalid_capture_length', index)
            if captured != original:
                raise Rejection('incomplete_capture', index)
            frame = stream.read(captured)
            if len(frame) != captured:
                raise Rejection('truncated_record_data', index)
            validate_packet(frame, linktype, index)
            previous = timestamp_ns
            count += 1
    if not count:
        raise Rejection('empty_capture')
    return {'accepted': True, 'packet_count': count, 'linktype': linktype}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pcap', type=Path)
    args = parser.parse_args(argv)
    try:
        result = inspect_pcap(args.pcap)
    except Rejection as exc:
        print(json.dumps({'accepted': False, 'reason': exc.reason, 'packet_index': exc.packet_index}))
        return 2
    except OSError as exc:
        print(json.dumps({'accepted': False, 'reason': 'io_error', 'detail': str(exc)}), file=sys.stderr)
        return 1
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
