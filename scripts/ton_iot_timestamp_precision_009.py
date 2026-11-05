"""Inspect timestamp-second boundaries for already-consumed development keys."""
import csv
import hashlib
import ipaddress
import json
import struct
import sys
import zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts.ton_iot_scanning_probe_009 import sha, decode
from scripts.ton_iot_unmatched_diagnostic_009 import ZIP, CSV, MEMBER, LOW, HIGH, EXPECTED_ZIP, EXPECTED_CSV, EXPECTED_MEMBER

PLAN=ROOT/'docs/EXPERIMENT-009-TIMESTAMP-ROUNDING-PLAN.md'
OUT=ROOT/'artifacts/experiment-009-timestamp-precision'
PRIOR=ROOT/'artifacts/experiment-009-unmatched-diagnostic/report.json'


def main():
    if OUT.exists(): raise FileExistsError(OUT)
    if sha(ZIP)!=EXPECTED_ZIP or sha(CSV)!=EXPECTED_CSV: raise ValueError('input hash mismatch')
    prior=json.loads(PRIOR.read_text(encoding='utf-8'))
    prior_hash=sha(PRIOR); dependencies=[Path(__file__),PLAN,ROOT/'scripts/ton_iot_scanning_probe_009.py',ROOT/'scripts/ton_iot_unmatched_diagnostic_009.py']
    hashes={p.relative_to(ROOT).as_posix():sha(p) for p in dependencies}
    OUT.mkdir(parents=True)
    protocol={'zip_sha256':EXPECTED_ZIP,'csv_sha256':EXPECTED_CSV,'prior_report_sha256':prior_hash,
              'dependencies':hashes,'sample':'first 50000 previously selected event keys','clock_shift':'none'}
    (OUT/'protocol.json').write_text(json.dumps(protocol,indent=2)+'\n',encoding='utf-8')
    selected=set()
    with CSV.open(encoding='utf-8-sig',newline='') as f:
        reader=csv.reader(f)
        if next(reader)!=['ts','src_ip','src_port','dst_ip','dst_port','proto','type']: raise ValueError('CSV schema')
        for row in reader:
            if len(row)!=7: continue
            try:
                second=int(row[0]); proto={'tcp':6,'udp':17}[row[5].lower()]
                key=(second,proto,ipaddress.IPv4Address(row[1]).packed,int(row[2]),ipaddress.IPv4Address(row[3]).packed,int(row[4]))
                if not 0<=key[3]<=65535 or not 0<=key[5]<=65535: continue
            except (ValueError,KeyError): continue
            if LOW<=second<=HIGH: selected.add(key)
            if len(selected)==50000: break
    if len(selected)!=50000: raise ValueError('sample selection mismatch')
    same=set(); ahead=set(); behind=set(); earlier_upper=set(); earlier_lower=set(); digest=hashlib.sha256(); packet_count=0
    with zipfile.ZipFile(ZIP) as z,z.open(MEMBER) as f:
        def read(n):
            data=f.read(n);digest.update(data);return data
        header=read(24)
        if len(header)!=24 or header[:4]!=bytes.fromhex('d4c3b2a1'): raise ValueError('expected little-endian microsecond pcap')
        _,major,minor,_,_,snap,link=struct.unpack('<IHHIIII',header)
        if (major,minor,link)!=(2,4,113): raise ValueError('unexpected capture format')
        while True:
            h=read(16)
            if not h: break
            if len(h)!=16: raise ValueError('truncated packet header')
            sec,micro,cap,orig=struct.unpack('<IIII',h)
            if micro>=1000000 or cap>orig or (snap and cap>snap) or cap>64*1024*1024: raise ValueError('invalid packet header')
            frame=read(cap)
            if len(frame)!=cap: raise ValueError('truncated packet')
            packet_count+=1; decoded=decode(frame,link)
            if decoded is None: continue
            p,src,sp,dst,dp=decoded
            for tuple5 in (decoded,(p,dst,dp,src,sp)):
                key=(sec,*tuple5)
                if key in selected: same.add(key)
                event_ahead=(sec+1,*tuple5)
                if event_ahead in selected:
                    ahead.add(event_ahead)
                    (earlier_upper if micro>=500000 else earlier_lower).add(event_ahead)
                event_behind=(sec-1,*tuple5)
                if event_behind in selected: behind.add(event_behind)
    if digest.hexdigest()!=EXPECTED_MEMBER: raise ValueError('capture member hash mismatch')
    adjacent=(ahead|behind)-same
    if len(same)!=27055 or len(adjacent)!=22945 or prior['categories']['same_second']!=len(same) or prior['categories']['within_1s_only']!=len(adjacent):
        raise ValueError('prior counts not reproduced')
    if sha(ZIP)!=EXPECTED_ZIP or sha(CSV)!=EXPECTED_CSV or sha(PRIOR)!=prior_hash or any(sha(ROOT/p)!=h for p,h in hashes.items()): raise ValueError('input changed during scan')
    result={'status':'complete','selected':len(selected),'same_second':len(same),'adjacent_only':len(adjacent),
            'adjacent_only_event_one_second_ahead_of_packet':len(adjacent&ahead),
            'adjacent_only_event_one_second_behind_packet':len(adjacent&behind),
            'adjacent_only_both_directions_in_time':len(adjacent&ahead&behind),
            'adjacent_only_ahead_with_packet_fraction_at_least_half':len(adjacent&earlier_upper),
            'adjacent_only_ahead_with_packet_fraction_below_half':len(adjacent&earlier_lower),
            'adjacent_only_ahead_with_both_fraction_categories':len(adjacent&earlier_upper&earlier_lower),
            'packets_scanned':packet_count,'member_sha256':digest.hexdigest(),'crc_verified':True,
            'protocol_sha256':sha(OUT/'protocol.json')}
    (OUT/'report.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result))


if __name__=='__main__': main()
