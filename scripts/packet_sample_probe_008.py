"""Cross-check TCP flags for 20 preselected source rows against one PCAP segment."""
import csv
import io
import ipaddress
import json
import struct
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from attack_traffic.experiment007_input import ALIASES, ARCHIVES, sha256
from attack_traffic.prepare import FEATURES
from attack_traffic.support_extract import feature_digest
from scripts.assess_experiment007 import write_json

SOURCE = ROOT / 'data/cicddos2019' / ARCHIVES['assessment'][0]
PCAP = ROOT / 'data/cicddos2019/pcaps/SAT-03-11-2018_0137.pcap'
OUT = ROOT / 'artifacts/experiment-008-packet-sample'
DIGEST = '7f6878da00b2931ae4427e1984698884a011aa2d39452d724f1ce62a6d1d46d5'
PCAP_SHA = 'e8d76130a6e5014177a9260345495fc48ac667fc31f92782748621cac69c43bc'
MEMBER = '03-11/UDPLag.csv'


def tcp_tuple_and_flags(frame):
    """Decode Ethernet/VLAN IPv4 TCP headers; skip noninitial fragments."""
    if len(frame) < 14:
        return None
    offset, etype = 14, int.from_bytes(frame[12:14], 'big')
    for _ in range(4):
        if etype not in (0x8100, 0x88a8, 0x9100):
            break
        if len(frame) < offset + 4:
            return None
        etype, offset = int.from_bytes(frame[offset+2:offset+4], 'big'), offset + 4
    if etype != 0x0800 or len(frame) < offset+20 or frame[offset] >> 4 != 4:
        return None
    iplen = (frame[offset] & 15) * 4
    if iplen < 20 or len(frame) < offset+iplen+20 or frame[offset+9] != 6:
        return None
    if int.from_bytes(frame[offset+6:offset+8], 'big') & 0x1fff:
        return None
    tcp = offset+iplen
    tcplen = (frame[tcp+12] >> 4) * 4
    if tcplen < 20 or len(frame) < tcp+tcplen or int.from_bytes(frame[offset+2:offset+4], 'big') < iplen+tcplen:
        return None
    source, dest = frame[offset+12:offset+16], frame[offset+16:offset+20]
    srcport, dstport = struct.unpack_from('!HH', frame, tcp)
    return (source, srcport, dest, dstport), frame[tcp+13]


def main():
    if sha256(SOURCE) != ARCHIVES['assessment'][1] or sha256(PCAP) != PCAP_SHA:
        raise ValueError('Source hash mismatch')
    candidates, lookup = [], {}
    with zipfile.ZipFile(SOURCE) as zf, zf.open(MEMBER) as raw, io.TextIOWrapper(raw, encoding='utf-8-sig', newline='') as text:
        reader = csv.reader(text)
        headers = [x.strip() for x in next(reader)]
        if len(headers) != 88 or len(set(headers)) != 88:
            raise ValueError('Unexpected header')
        fi = [headers.index(ALIASES.get(n, n)) for n in FEATURES]
        names = ('Source IP','Source Port','Destination IP','Destination Port','Timestamp','Label','Protocol','SYN Flag Count','ACK Flag Count','URG Flag Count','Flow Duration')
        idx = {name: headers.index(name) for name in names}
        for line, row in enumerate(reader, 2):
            if len(row) != 88:
                raise ValueError('Malformed CSV row')
            stamp = row[idx['Timestamp']].strip()
            if row[idx['Label']].strip() != 'Syn' or not ('2018-11-03 11:29:00' <= stamp < '2018-11-03 11:30:26'):
                continue
            if feature_digest([float(row[i]) for i in fi]) != DIGEST:
                continue
            key = (ipaddress.IPv4Address(row[idx['Source IP']].strip()).packed, int(row[idx['Source Port']]),
                   ipaddress.IPv4Address(row[idx['Destination IP']].strip()).packed, int(row[idx['Destination Port']]))
            reverse = (key[2], key[3], key[0], key[1])
            if key in lookup or reverse in lookup:
                continue
            if row[idx['Protocol']].strip() != '6':
                raise ValueError('Unexpected target protocol')
            item = {'record_number': line, 'csv_clock': stamp, 'csv_syn': int(row[idx['SYN Flag Count']]),
                    'csv_ack': int(row[idx['ACK Flag Count']]), 'csv_urg': int(row[idx['URG Flag Count']]),
                    'csv_duration_us': int(float(row[idx['Flow Duration']])), 'packets': []}
            lookup[key] = (len(candidates), 'forward'); lookup[reverse] = (len(candidates), 'reverse')
            candidates.append(item)
            if len(candidates) == 20:
                break
    if len(candidates) != 20:
        raise ValueError('Insufficient distinct source tuples')
    OUT.mkdir(parents=True, exist_ok=False)
    protocol = {'source_sha256': ARCHIVES['assessment'][1], 'pcap_sha256': PCAP_SHA, 'runner_sha256': sha256(Path(__file__)),
                'selection': 'first 20 distinct TCP tuples in CSV order, Syn label, fixed feature digest, source clock 11:29:00–11:30:25',
                'source_member': MEMBER, 'source_records': [x['record_number'] for x in candidates],
                'clock_comparison': 'post-hoc hypothesis PCAP UTC equals CSV clock plus three hours; not general timezone verification',
                'limitations': 'one selected feature group and one PCAP segment; tuple matches are not independently reconstructed flows'}
    write_json(OUT / 'protocol.json', protocol)
    packets = 0
    try:
        with PCAP.open('rb') as stream:
            header = stream.read(24)
            if len(header) != 24 or header[:4] != bytes.fromhex('d4c3b2a1'):
                raise ValueError('Expected microsecond little-endian classic PCAP')
            major, minor, _, _, snaplen, linktype = struct.unpack('<HHiIII', header[4:])
            if (major, minor) != (2, 4) or linktype != 1 or not 0 < snaplen <= 16*1024*1024:
                raise ValueError('Unexpected PCAP header or link type')
            while True:
                h = stream.read(16)
                if not h:
                    break
                if len(h) != 16:
                    raise ValueError('Truncated PCAP packet header')
                sec, micro, captured, original = struct.unpack('<IIII', h)
                if micro >= 1000000 or captured > original or captured > snaplen:
                    raise ValueError('Invalid packet record')
                frame = stream.read(captured)
                if len(frame) != captured:
                    raise ValueError('Truncated PCAP packet')
                packets += 1
                decoded = tcp_tuple_and_flags(frame)
                if decoded is not None and decoded[0] in lookup:
                    index, direction = lookup[decoded[0]]
                    item = candidates[index]
                    packet_time = datetime.fromtimestamp(sec, timezone.utc).replace(tzinfo=None, microsecond=micro)
                    delta = packet_time - datetime.fromisoformat(item['csv_clock'])
                    offset_us = (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds
                    item['packets'].append({'direction': direction, 'tcp_flags_hex': f'{decoded[1]:02x}', 'offset_from_csv_us': offset_us})
                if packets % 1000000 == 0:
                    write_json(OUT / 'progress.json', {'status':'running', 'packets_scanned':packets})
        for item in candidates:
            event = item['packets']
            item['exact_two_packet_candidate'] = (len(event) == 2 and all(p['direction']=='forward' and p['tcp_flags_hex']=='02' for p in event)
                and sorted(p['offset_from_csv_us'] for p in event) == [10800000000, 10800000000 + item['csv_duration_us']])
        if sha256(SOURCE) != protocol['source_sha256'] or sha256(PCAP) != protocol['pcap_sha256'] or sha256(Path(__file__)) != protocol['runner_sha256']:
            raise ValueError('Input changed during analysis')
        result = {'status':'complete', 'packets_scanned':packets, 'selected_flows':len(candidates),
                  'exact_two_packet_candidates':sum(x['exact_two_packet_candidate'] for x in candidates),
                  'candidates':candidates, 'protocol_sha256':sha256(OUT / 'protocol.json')}
        write_json(OUT / 'report.json', result)
        write_json(OUT / 'progress.json', {'status':'complete','packets_scanned':packets,'exact_two_packet_candidates':result['exact_two_packet_candidates']})
        print('Selected',len(candidates),'source flows;',result['exact_two_packet_candidates'],'matched the two-packet SYN pattern.')
    except BaseException as exc:
        write_json(OUT / 'progress.json', {'status':'failed','packets_scanned':packets,'error':repr(exc)})
        raise


if __name__ == '__main__':
    main()
