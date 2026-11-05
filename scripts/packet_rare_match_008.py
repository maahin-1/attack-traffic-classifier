"""Trace rare flags to all matching source CSV tuples; diagnostic only."""
import csv
import hashlib
import io
import ipaddress
import json
import struct
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from attack_traffic.experiment007_input import ARCHIVES, sha256
from scripts.assess_experiment007 import write_json
from scripts.packet_multi_inventory_008 import HashedReader
from scripts.packet_sample_probe_008 import tcp_tuple_and_flags

PCAP = ROOT / 'data/cicddos2019/pcaps/PCAP-03-11.zip'
CSV = ROOT / 'data/cicddos2019' / ARCHIVES['assessment'][0]
PCAP_HASH = 'cdc8935296cab7a2354d4fd32939f7d5e6c592371e5fb89d6a3094cc05dc38c5'
MEMBER = 'SAT-03-11-2018_0145'
MEMBER_HASH = 'eef2069b39526d1850e72140424b3b4910b11c8085dafbad85ed4fccd52bb749'
PLAN = ROOT / 'docs/EXPERIMENT-008-RARE-FLAG-MATCH-PLAN.md'
OUT = ROOT / 'artifacts/experiment-008-rare-flag-match'
FLAGS = ('FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'CWE', 'ECE')


def records(stream):
    header = stream.read(24)
    if len(header) != 24 or header[:4] != bytes.fromhex('d4c3b2a1'):
        raise ValueError('Unsupported PCAP magic')
    major, minor, _, _, snaplen, linktype = struct.unpack('<HHiIII', header[4:])
    if (major, minor) != (2, 4) or linktype != 1:
        raise ValueError('Unsupported PCAP header')
    while True:
        h = stream.read(16)
        if not h:
            return
        if len(h) != 16:
            yield {'truncated_header_bytes': len(h)}
            return
        sec, micro, size, orig = struct.unpack('<IIII', h)
        if micro >= 1000000 or size > snaplen or size > orig:
            raise ValueError('Invalid record header')
        frame = stream.read(size)
        if len(frame) != size:
            yield {'truncated_data_bytes': len(frame), 'expected': size}
            return
        yield (sec * 1000000 + micro, tcp_tuple_and_flags(frame))


def iso(us):
    return datetime.fromtimestamp(us // 1000000, timezone.utc).replace(microsecond=us % 1000000).isoformat()


def reverse(key):
    return (key[2], key[3], key[0], key[1])


def epoch_us(text):
    value = datetime.fromisoformat(text.strip()).replace(tzinfo=timezone.utc)
    delta = value - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds


def classify(event_us, start_us, duration_us, offset_us=10800000000):
    """Positions under a stated clock hypothesis, retaining exact boundaries."""
    relative = event_us - start_us - offset_us
    return 'before' if relative < 0 else 'after' if relative > duration_us else 'inside'


def main():
    if sha256(PCAP) != PCAP_HASH or sha256(CSV) != ARCHIVES['assessment'][1]:
        raise ValueError('Archive hash mismatch')
    deps = [Path(__file__), PLAN, ROOT/'scripts/packet_sample_probe_008.py', ROOT/'scripts/packet_multi_inventory_008.py']
    hashes = {p.relative_to(ROOT).as_posix(): sha256(p) for p in deps}
    OUT.mkdir(parents=True, exist_ok=False)
    protocol = {'pcap_archive_sha256': PCAP_HASH, 'csv_archive_sha256': ARCHIVES['assessment'][1],
                'capture_member': MEMBER, 'capture_member_sha256': MEMBER_HASH, 'dependencies': hashes,
                'clock_offset_us_hypothesis': 10800000000, 'scope': 'all source CSV rows with exact TCP tuple in either direction; no label or time filter'}
    write_json(OUT/'protocol.json', protocol)
    targets = {}; truncation = None; rare = []
    with zipfile.ZipFile(PCAP) as z:
        for passno in (1, 2):
            with z.open(MEMBER) as raw:
                stream = HashedReader(raw)
                for item in records(stream):
                    if isinstance(item, dict):
                        truncation = item
                        continue
                    when, decoded = item
                    if not decoded:
                        continue
                    key, mask = decoded
                    if passno == 1 and mask & 192:
                        canonical = min(key, reverse(key))
                        targets.setdefault(canonical, {'events': [], 'csv': []})
                        rare.append({'tuple_id': list(targets).index(canonical) + 1, 'utc': iso(when), 'time_us': when, 'mask': mask})
                    elif passno == 2:
                        canonical = min(key, reverse(key))
                        if canonical in targets:
                            targets[canonical]['events'].append({'time_us': when, 'utc': iso(when), 'direction': 'canonical' if key == canonical else 'reverse', 'mask': mask})
                if stream.digest.hexdigest() != MEMBER_HASH:
                    raise ValueError('Capture member hash mismatch')
    if len(rare) != 2:
        raise ValueError(f'Expected two rare packets, observed {len(rare)}')
    lookup = {}
    for canonical in targets:
        for key in (canonical, reverse(canonical)):
            lookup[(str(ipaddress.IPv4Address(key[0])), str(key[1]), str(ipaddress.IPv4Address(key[2])), str(key[3]))] = (canonical, key == canonical)
    write_json(OUT/'progress.json', {'phase': 'pcap complete', 'rare_packets': len(rare), 'distinct_bidirectional_tuples': len(targets)})
    members = {}; all_names = []
    with zipfile.ZipFile(CSV) as z:
        all_names = [i.filename for i in z.infolist() if i.filename.lower().endswith('.csv') and not i.is_dir()]
        for name in all_names:
            with z.open(name) as raw, io.TextIOWrapper(raw, encoding='utf-8-sig', newline='') as stream:
                reader = csv.reader(stream)
                headers = [h.strip() for h in next(reader)]
                required = ['Source IP','Source Port','Destination IP','Destination Port','Protocol','Timestamp','Flow Duration','Total Fwd Packets','Total Backward Packets','Label'] + [f+' Flag Count' for f in FLAGS]
                if len(headers) != 88 or len(set(headers)) != 88 or any(n not in headers for n in required):
                    raise ValueError(f'Unexpected CSV header in {name}')
                ix = {n: headers.index(n) for n in required}
                count = 0; hits = 0
                for line, row in enumerate(reader, 2):
                    count += 1
                    if len(row) != len(headers):
                        raise ValueError(f'Malformed row {name}:{line}')
                    if row[ix['Protocol']].strip() != '6':
                        continue
                    key = tuple(row[ix[n]].strip() for n in ('Source IP','Source Port','Destination IP','Destination Port'))
                    if key not in lookup:
                        continue
                    canonical, is_canonical = lookup[key]
                    hits += 1
                    start = epoch_us(row[ix['Timestamp']]); duration = float(row[ix['Flow Duration']])
                    if not duration.is_integer() or duration < 0:
                        raise ValueError('Invalid matching flow duration')
                    event_list = targets[canonical]['events']
                    positions = {p: sum(classify(e['time_us'], start, int(duration)) == p for e in event_list) for p in ('before','inside','after')}
                    targets[canonical]['csv'].append({'member':name, 'record':line, 'clock':row[ix['Timestamp']].strip(), 'duration_us':int(duration),
                        'direction':'canonical' if is_canonical else 'reverse', 'forward_packets':row[ix['Total Fwd Packets']].strip(),
                        'backward_packets':row[ix['Total Backward Packets']].strip(), 'label':row[ix['Label']].strip(),
                        'flags':{f:row[ix[f+' Flag Count']].strip() for f in FLAGS}, 'tuple_packet_positions_at_plus3h':positions,
                        'rare_packet_deltas_from_csv_start_us':[e['time_us']-start for e in rare if e['tuple_id']==list(targets).index(canonical)+1]})
                members[name] = {'rows': count, 'tuple_matches': hits, 'crc_verified_by_full_read': True}
            write_json(OUT/'progress.json', {'phase':'csv scan', 'completed':members})
    if sha256(PCAP) != PCAP_HASH or sha256(CSV) != ARCHIVES['assessment'][1] or any(sha256(ROOT/p)!=h for p,h in hashes.items()):
        raise ValueError('Source or implementation changed during run')
    output = []
    for i, (key, value) in enumerate(targets.items(), 1):
        # The tuple itself stays in memory only; the ordinal connects related observations.
        output.append({'tuple_id':i, **value})
    report = {'status':'complete', 'rare_packets':rare, 'tuples':output, 'csv_members':members,
              'capture_truncated_final_record':truncation, 'protocol_sha256':sha256(OUT/'protocol.json')}
    write_json(OUT/'report.json', report)
    write_json(OUT/'progress.json', {'phase':'complete', 'csv_members':len(members)})
    print(json.dumps({'rare':len(rare), 'tuples':len(targets), 'csv_rows':sum(x['rows'] for x in members.values()), 'csv_matches':sum(x['tuple_matches'] for x in members.values())}))


if __name__ == '__main__':
    main()
