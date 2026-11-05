"""Post-hoc, flag-stratified comparison of CSV fields and captured TCP flags."""
import csv
import io
import ipaddress
import json
import struct
import sys
import zipfile
from collections import Counter, defaultdict
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
PCAP_SHA = 'e8d76130a6e5014177a9260345495fc48ac667fc31f92782748621cac69c43bc'
MEMBER = '03-11/UDPLag.csv'
PLAN = ROOT / 'docs/EXPERIMENT-008-FLAG-STRATIFIED-PLAN.md'
OUT = ROOT / 'artifacts/experiment-008-packet-stratified'
CSV_FLAGS = ('FIN','SYN','RST','PSH','ACK','URG','CWE','ECE')
TCP_FLAGS = {'FIN':1,'SYN':2,'RST':4,'PSH':8,'ACK':16,'URG':32,'ECE':64,'CWR':128}
OFFSET = 10800000000


def flag_agreements(observations):
    """Compare binary CSV values with each first-packet bit, without assigning a mapping."""
    return {column:{'csv_positive':sum(o['csv_flags'][column] > 0 for o in observations),
                    'agreement':{name:sum((o['csv_flags'][column]>0)==bool(o['first_mask'] & bit) for o in observations)
                                 for name,bit in TCP_FLAGS.items()}} for column in CSV_FLAGS}


def main():
    if sha256(SOURCE)!=ARCHIVES['assessment'][1] or sha256(PCAP)!=PCAP_SHA:
        raise ValueError('Input hash mismatch')
    records=[]; lookup={}; groups=defaultdict(set); selected_patterns=Counter(); eligible=Counter()
    with zipfile.ZipFile(SOURCE) as zf,zf.open(MEMBER) as raw,io.TextIOWrapper(raw,encoding='utf-8-sig',newline='') as text:
        r=csv.reader(text); headers=[x.strip() for x in next(r)]
        if len(headers)!=88 or len(set(headers))!=88: raise ValueError('Unexpected CSV header')
        fi=[headers.index(ALIASES.get(n,n)) for n in FEATURES]
        names=('Source IP','Source Port','Destination IP','Destination Port','Timestamp','Label','Protocol','Flow Duration','Total Fwd Packets','Total Backward Packets')
        ix={n:headers.index(n) for n in names}; fx={n:headers.index(n+' Flag Count') for n in CSV_FLAGS}
        for line,row in enumerate(r,2):
            if len(row)!=88: raise ValueError('Malformed source row')
            stamp=row[ix['Timestamp']].strip()
            if row[ix['Protocol']].strip()!='6' or not ('2018-11-03 11:15:00'<=stamp<'2018-11-03 11:30:00'): continue
            duration=float(row[ix['Flow Duration']])
            if float(row[ix['Total Fwd Packets']])!=2 or float(row[ix['Total Backward Packets']])!=0 or not (1<=duration<=1000 and duration.is_integer()): continue
            numeric={name:float(row[i]) for name,i in fx.items()}
            if any(v not in (0.0,1.0) for v in numeric.values()): raise ValueError('Non-binary flag value in candidate scope')
            values={name:int(v) for name,v in numeric.items()}
            pattern=tuple(name for name in CSV_FLAGS if values[name])
            eligible[','.join(pattern)]+=1
            if len(groups[pattern])>=20: continue
            digest=feature_digest([float(row[i]) for i in fi])
            if digest in groups[pattern]: continue
            key=(ipaddress.IPv4Address(row[ix['Source IP']].strip()).packed,int(row[ix['Source Port']]),
                 ipaddress.IPv4Address(row[ix['Destination IP']].strip()).packed,int(row[ix['Destination Port']]))
            reverse=(key[2],key[3],key[0],key[1])
            if key in lookup or reverse in lookup: continue
            lookup[key]=(len(records),'forward'); lookup[reverse]=(len(records),'reverse')
            groups[pattern].add(digest); selected_patterns[','.join(pattern)]+=1
            records.append({'record_number':line,'label':row[ix['Label']].strip(),'csv_clock':stamp,'duration_us':int(duration),
                            'csv_flags':values,'packets_in_window':[],'tuple_packets_outside_window':0})
    if not records: raise ValueError('No eligible source records')
    OUT.mkdir(parents=True,exist_ok=False)
    dependencies=[Path(__file__),PLAN,ROOT/'scripts/packet_sample_probe_008.py',ROOT/'attack_traffic/support_extract.py',ROOT/'attack_traffic/prepare.py',ROOT/'attack_traffic/experiment007_input.py']
    hashes={p.relative_to(ROOT).as_posix():sha256(p) for p in dependencies}
    protocol={'source_sha256':ARCHIVES['assessment'][1],'pcap_sha256':PCAP_SHA,'dependencies':hashes,
              'selection':'first up to 20 distinct feature groups and bidirectional tuples per CSV flag pattern in fixed development scope',
              'selection_disclosure':'post-hoc flag-stratified convenience sample; source pattern inventory and prior packet results were observed',
              'offset_us_hypothesis':OFFSET,'eligible_patterns':dict(eligible),'selected_patterns':dict(selected_patterns),
              'source_records':[x['record_number'] for x in records]}
    write_json(OUT/'protocol.json',protocol)
    count=0
    try:
        with PCAP.open('rb') as stream:
            header=stream.read(24)
            if len(header)!=24 or header[:4]!=bytes.fromhex('d4c3b2a1'): raise ValueError('Expected little-endian microsecond PCAP')
            major,minor,_,_,snaplen,linktype=struct.unpack('<HHiIII',header[4:])
            if (major,minor)!=(2,4) or linktype!=1 or not 0<snaplen<=16*1024*1024: raise ValueError('Unsupported PCAP header')
            while True:
                h=stream.read(16)
                if not h: break
                if len(h)!=16: raise ValueError('Truncated packet header')
                sec,micro,size,original=struct.unpack('<IIII',h)
                if micro>=1000000 or size>original or size>snaplen: raise ValueError('Invalid packet record')
                frame=stream.read(size)
                if len(frame)!=size: raise ValueError('Truncated packet')
                count+=1; decoded=tcp_tuple_and_flags(frame)
                if decoded is None or decoded[0] not in lookup: continue
                i,direction=lookup[decoded[0]]; item=records[i]
                stamp=datetime.fromtimestamp(sec,timezone.utc).replace(tzinfo=None,microsecond=micro)
                delta=stamp-datetime.fromisoformat(item['csv_clock']); offset=(delta.days*86400+delta.seconds)*1000000+delta.microseconds
                if OFFSET<=offset<=OFFSET+item['duration_us']:
                    item['packets_in_window'].append({'offset_us':offset-OFFSET,'direction':direction,'flags':decoded[1]})
                else: item['tuple_packets_outside_window']+=1
        matched=[]
        for row in records:
            events=sorted(row['packets_in_window'],key=lambda x:x['offset_us'])
            row['matched_two_forward_packets']=(len(events)==2 and all(e['direction']=='forward' for e in events) and events[0]['offset_us']==0 and events[-1]['offset_us']==row['duration_us'])
            if row['matched_two_forward_packets']:
                matched.append({'csv_flags':row['csv_flags'],'first_mask':events[0]['flags']})
        if sha256(SOURCE)!=protocol['source_sha256'] or sha256(PCAP)!=protocol['pcap_sha256']:
            raise ValueError('Source changed during inspection')
        for p,digest in hashes.items():
            if sha256(ROOT/p)!=digest: raise ValueError(f'Dependency changed: {p}')
        report={'status':'complete','packets_scanned':count,'selected':len(records),'matched':len(matched),
                'ambiguous_or_unmatched':len(records)-len(matched),'matched_with_other_tuple_packets':sum(r['matched_two_forward_packets'] and r['tuple_packets_outside_window']>0 for r in records),
                'records':records,'first_packet_bit_positive':{name:sum(bool(o['first_mask']&bit) for o in matched) for name,bit in TCP_FLAGS.items()},
                'agreements':flag_agreements(matched),'protocol_sha256':sha256(OUT/'protocol.json')}
        write_json(OUT/'report.json',report)
        print(json.dumps({k:report[k] for k in ('status','packets_scanned','selected','matched','ambiguous_or_unmatched','first_packet_bit_positive')}))
    except BaseException as exc:
        write_json(OUT/'failure.json',{'status':'failed','packets_scanned':count,'error':repr(exc)})
        raise


if __name__=='__main__': main()
