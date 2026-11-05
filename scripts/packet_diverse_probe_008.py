"""Exploratory TCP flag comparison across multiple assessment feature groups."""
import csv
import io
import ipaddress
import json
import struct
import sys
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from attack_traffic.experiment007_input import ALIASES, ARCHIVES, sha256
from attack_traffic.prepare import FEATURES
from attack_traffic.support_extract import feature_digest
from scripts.assess_experiment007 import write_json
from scripts.packet_sample_probe_008 import tcp_tuple_and_flags

SOURCE = ROOT / 'data/cicddos2019' / ARCHIVES['assessment'][0]
PCAP = ROOT / 'data/cicddos2019/pcaps/SAT-03-11-2018_0137.pcap'
OUT = ROOT / 'artifacts/experiment-008-packet-diverse'
PCAP_SHA = 'e8d76130a6e5014177a9260345495fc48ac667fc31f92782748621cac69c43bc'
MEMBER = '03-11/UDPLag.csv'
FLAGS = {'FIN':1, 'SYN':2, 'RST':4, 'PSH':8, 'ACK':16, 'URG':32, 'ECE':64}
OFFSET = 10800000000


def compare_flags(csv_flags, packets):
    """Return per-flag agreement with first packet and sum across packets."""
    first = {k: int(bool(packets[0] & bit)) for k, bit in FLAGS.items()}
    full = {k: sum(bool(p & bit) for p in packets) for k, bit in FLAGS.items()}
    return {'first_packet': first, 'all_packets': full,
            'matches_first': {k: csv_flags[k] == first[k] for k in FLAGS},
            'matches_full': {k: csv_flags[k] == full[k] for k in FLAGS}}


def main():
    if sha256(SOURCE) != ARCHIVES['assessment'][1] or sha256(PCAP) != PCAP_SHA:
        raise ValueError('Input hash mismatch')
    candidates, lookup, groups = [], {}, {'BENIGN':set(), 'Syn':set()}
    with zipfile.ZipFile(SOURCE) as zf, zf.open(MEMBER) as raw, io.TextIOWrapper(raw, encoding='utf-8-sig', newline='') as text:
        reader = csv.reader(text)
        headers = [x.strip() for x in next(reader)]
        if len(headers) != 88 or len(set(headers)) != 88:
            raise ValueError('Unexpected source header')
        fi = [headers.index(ALIASES.get(n,n)) for n in FEATURES]
        fields = ('Source IP','Source Port','Destination IP','Destination Port','Timestamp','Label','Protocol',
                  'Flow Duration','Total Fwd Packets','Total Backward Packets')
        idx = {n:headers.index(n) for n in fields}
        flag_idx = {n:headers.index(n + ' Flag Count') for n in FLAGS}
        for line, row in enumerate(reader, 2):
            if len(row) != 88:
                raise ValueError('Malformed source row')
            label, stamp = row[idx['Label']].strip(), row[idx['Timestamp']].strip()
            if label not in groups or len(groups[label]) >= 20 or row[idx['Protocol']].strip() != '6' or not ('2018-11-03 11:15:00' <= stamp < '2018-11-03 11:30:00'):
                continue
            duration = float(row[idx['Flow Duration']])
            if float(row[idx['Total Fwd Packets']]) != 2 or float(row[idx['Total Backward Packets']]) != 0 or not (0 <= duration <= 1000 and duration.is_integer()):
                continue
            digest = feature_digest([float(row[i]) for i in fi])
            if digest in groups[label]:
                continue
            key = (ipaddress.IPv4Address(row[idx['Source IP']].strip()).packed, int(row[idx['Source Port']]),
                   ipaddress.IPv4Address(row[idx['Destination IP']].strip()).packed, int(row[idx['Destination Port']]))
            reverse = (key[2], key[3], key[0], key[1])
            if key in lookup or reverse in lookup:
                continue
            item = {'record_number':line, 'label':label, 'csv_clock':stamp, 'duration_us':int(duration),
                    'csv_flags':{n:int(float(row[i])) for n,i in flag_idx.items()}, 'packets_in_window':[], 'tuple_packets_outside_window':0}
            groups[label].add(digest)
            lookup[key]=(len(candidates),'forward'); lookup[reverse]=(len(candidates),'reverse')
            candidates.append(item)
            if all(len(x) == 20 for x in groups.values()):
                break
    if not all(len(x) == 20 for x in groups.values()):
        raise ValueError('Could not find 20 distinct feature groups per source label')
    OUT.mkdir(parents=True, exist_ok=False)
    protocol = {'source_sha256':ARCHIVES['assessment'][1], 'pcap_sha256':PCAP_SHA, 'runner_sha256':sha256(Path(__file__)),
                'decoder_sha256':sha256(ROOT / 'scripts/packet_sample_probe_008.py'), 'feature_digest_sha256':sha256(ROOT / 'attack_traffic/support_extract.py'),
                'selection':'first 20 distinct 27-feature groups per BENIGN/Syn label, unique TCP tuple, two forward and zero backward packets, duration 0–1000us, CSV time 11:15–11:30',
                'selection_note':'post-assessment convenience sample chosen after the first 20-flow result; not random or independent',
                'offset_policy':'use previously observed +3h hypothesis to find packets in CSV duration window; no global timezone claim',
                'source_records':[{'record_number':x['record_number'],'label':x['label']} for x in candidates]}
    write_json(OUT / 'protocol.json', protocol)
    count = 0
    try:
        with PCAP.open('rb') as stream:
            header = stream.read(24)
            if len(header)!=24 or header[:4]!=bytes.fromhex('d4c3b2a1'):
                raise ValueError('Expected little-endian microsecond PCAP')
            major,minor,_,_,snaplen,linktype=struct.unpack('<HHiIII',header[4:])
            if (major,minor)!=(2,4) or linktype!=1 or not 0<snaplen<=16*1024*1024:
                raise ValueError('Unsupported capture header')
            while True:
                h=stream.read(16)
                if not h: break
                if len(h)!=16: raise ValueError('Truncated packet header')
                sec,micro,size,original=struct.unpack('<IIII',h)
                if micro>=1000000 or size>original or size>snaplen: raise ValueError('Invalid packet')
                frame=stream.read(size)
                if len(frame)!=size: raise ValueError('Truncated packet')
                count+=1
                decoded=tcp_tuple_and_flags(frame)
                if decoded is None or decoded[0] not in lookup: continue
                index,direction=lookup[decoded[0]]; item=candidates[index]
                packet_time=datetime.fromtimestamp(sec,timezone.utc).replace(tzinfo=None,microsecond=micro)
                delta=packet_time-datetime.fromisoformat(item['csv_clock'])
                offset=(delta.days*86400+delta.seconds)*1000000+delta.microseconds
                if OFFSET <= offset <= OFFSET+item['duration_us']:
                    item['packets_in_window'].append({'offset_us':offset-OFFSET,'direction':direction,'flags':decoded[1]})
                else: item['tuple_packets_outside_window']+=1
        summary={label:{'selected':20,'matched_two_forward_packets':0,'flag_comparisons':{n:{'matches_first':0,'matches_full':0} for n in FLAGS}} for label in groups}
        for item in candidates:
            events=sorted(item['packets_in_window'],key=lambda x:x['offset_us'])
            valid=len(events)==2 and all(e['direction']=='forward' for e in events) and events[0]['offset_us']==0 and events[1]['offset_us']==item['duration_us']
            item['matched_two_forward_packets']=valid
            if not valid: continue
            comparison=compare_flags(item['csv_flags'],[e['flags'] for e in events])
            item['comparison']=comparison
            result=summary[item['label']]; result['matched_two_forward_packets']+=1
            for n in FLAGS:
                result['flag_comparisons'][n]['matches_first']+=comparison['matches_first'][n]
                result['flag_comparisons'][n]['matches_full']+=comparison['matches_full'][n]
        for path, expected in ((SOURCE,protocol['source_sha256']),(PCAP,protocol['pcap_sha256']),(Path(__file__),protocol['runner_sha256']),
                               (ROOT/'scripts/packet_sample_probe_008.py',protocol['decoder_sha256']),(ROOT/'attack_traffic/support_extract.py',protocol['feature_digest_sha256'])):
            if sha256(path)!=expected: raise ValueError(f'Input changed: {path.name}')
        report={'status':'complete','packets_scanned':count,'summary':summary,'candidates':candidates,'protocol_sha256':sha256(OUT/'protocol.json')}
        write_json(OUT/'report.json',report)
        print(json.dumps({'status':'complete','packets_scanned':count,'summary':summary}))
    except BaseException as exc:
        write_json(OUT/'failure.json',{'status':'failed','error':repr(exc),'packets_scanned':count})
        raise


if __name__=='__main__':
    main()
