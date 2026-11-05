"""Aggregate post-hoc tuple/time match categories for consumed development data."""
import bisect
import csv
import hashlib
import ipaddress
import json
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts.ton_iot_scanning_probe_009 import sha
from scripts.ton_iot_scanning1_probe_009 import packets

ZIP=ROOT/'data/ton_iot/development/pcaps/normal_scanning.zip'
CSV=ROOT/'data/ton_iot/development/metadata/GroundTruth_Network_1.csv'
PREVIOUS=ROOT/'artifacts/experiment-009-scanning1-probe/report.json'
MEMBER='normal_scanning/normal_scanning1.pcap'
PLAN=ROOT/'docs/EXPERIMENT-009-UNMATCHED-DIAGNOSTIC-PLAN.md'
OUT=ROOT/'artifacts/experiment-009-unmatched-diagnostic'
EXPECTED_ZIP='0c62e650d62365043228b4268cf9ef5571c7b3aa950f489d7941c98214026ba5'
EXPECTED_CSV='79f2d99bf34965126480bc2f18949b67f7fc0a26c135c24a88f9aae700913f28'
EXPECTED_REPORT='bcd3ca518be20eb65d80439c97b94cbf6cfe249636377600d082680f2d51feae'
EXPECTED_MEMBER='464f17996a5158964fc5ef4e48e6f108ea70b834bccc973e94e730371c1c51c5'
LOW=1556021409
HIGH=1556025302


def add_window(index,second,found):
    """Collect event indices within fixed integer-second windows of one packet."""
    low=bisect.bisect_left(index,(second-60,-1)); high=bisect.bisect_right(index,(second+60,10**9))
    for event_second,event_id in index[low:high]:
        difference=abs(second-event_second)
        for bound in (0,1,5,60):
            if difference<=bound: found[bound].add(event_id)


def partition(ids,found,any_ids):
    remaining=set(ids); counts={}
    for bound,label in ((0,'same_second'),(1,'within_1s_only'),(5,'within_5s_only'),(60,'within_60s_only')):
        group=remaining & found[bound]; counts[label]=len(group); remaining-=group
    group=remaining & any_ids; counts['tuple_only_outside_60s']=len(group); remaining-=group
    counts['tuple_not_seen']=len(remaining)
    return counts


def main():
    if OUT.exists(): raise FileExistsError(OUT)
    inputs={ZIP:EXPECTED_ZIP,CSV:EXPECTED_CSV,PREVIOUS:EXPECTED_REPORT}
    if any(sha(path)!=expected for path,expected in inputs.items()): raise ValueError('source hash mismatch')
    dependencies=[Path(__file__),PLAN,ROOT/'scripts/ton_iot_scanning_probe_009.py',ROOT/'scripts/ton_iot_scanning1_probe_009.py']
    hashes={p.relative_to(ROOT).as_posix():sha(p) for p in dependencies}
    OUT.mkdir(parents=True)
    protocol={'inputs':{p.relative_to(ROOT).as_posix():h for p,h in inputs.items()},'dependencies':hashes,
              'selection':'first 50000 distinct eligible directional TCP/UDP IPv4 keys in original CSV order',
              'capture_range_inclusive':[LOW,HIGH],'time_windows_seconds':[0,1,5,60],
              'scope':'post-hoc diagnostic, not independent evaluation or model selection'}
    (OUT/'protocol.json').write_text(json.dumps(protocol,indent=2)+'\n',encoding='utf-8')
    keys=[]; seen=set()
    with CSV.open(encoding='utf-8-sig',newline='') as f:
        reader=csv.reader(f)
        if next(reader)!=['ts','src_ip','src_port','dst_ip','dst_port','proto','type']: raise ValueError('CSV schema mismatch')
        for row in reader:
            if len(row)!=7: continue
            try:
                second=int(row[0]); proto={'tcp':6,'udp':17}[row[5].lower()]
                key=(second,proto,ipaddress.IPv4Address(row[1]).packed,int(row[2]),ipaddress.IPv4Address(row[3]).packed,int(row[4]))
                if not 0<=key[3]<=65535 or not 0<=key[5]<=65535: continue
            except (ValueError,KeyError): continue
            if LOW<=second<=HIGH and key not in seen:
                keys.append(key); seen.add(key)
                if len(keys)==50000: break
    if len(keys)!=50000: raise ValueError('Selection does not reproduce')
    index=defaultdict(list)
    for i,(sec,p,src,sp,dst,dp) in enumerate(keys): index[(p,src,sp,dst,dp)].append((sec,i))
    for entries in index.values(): entries.sort()
    found={n:set() for n in (0,1,5,60)}; tuple_seen=set(); stats=Counter(); member_hash=hashlib.sha256()
    class HashReader:
        def __init__(self,source): self.source=source
        def read(self,n):
            b=self.source.read(n); member_hash.update(b); return b
    with zipfile.ZipFile(ZIP) as z, z.open(MEMBER) as raw:
        for second,key in packets(HashReader(raw),stats):
            if key is None: continue
            p,src,sp,dst,dp=key
            for query in (key,(p,dst,dp,src,sp)):
                if query in index:
                    tuple_seen.add(query); add_window(index[query],second,found)
    if member_hash.hexdigest()!=EXPECTED_MEMBER: raise ValueError('capture member changed')
    previous=json.loads(PREVIOUS.read_text(encoding='utf-8'))
    expected_same=len(keys)-previous['match']['unmatched_either_direction']
    if len(found[0])!=expected_same or expected_same!=27055: raise ValueError('prior same-second agreement not reproduced')
    any_ids={i for key in tuple_seen for _,i in index[key]}
    categories=partition(range(len(keys)),found,any_ids)
    by_protocol={}
    for proto,name in ((6,'tcp'),(17,'udp')):
        ids={i for i,k in enumerate(keys) if k[1]==proto}
        by_protocol[name]={'selected':len(ids),'categories':partition(ids,found,any_ids)}
    if sum(categories.values())!=len(keys): raise ValueError('category totals do not reconcile')
    if any(sha(path)!=expected for path,expected in inputs.items()) or any(sha(ROOT/p)!=h for p,h in hashes.items()): raise ValueError('input changed during scan')
    report={'status':'complete','selected_event_keys':len(keys),'previous_same_second_reproduced':len(found[0]),
            'categories':categories,'by_protocol':by_protocol,'packets_scanned':stats['packets'],
            'capture_member_sha256':member_hash.hexdigest(),'zip_member_crc_verified':True,
            'protocol_sha256':sha(OUT/'protocol.json')}
    (OUT/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    print(json.dumps({'status':report['status'],'categories':categories,'by_protocol':by_protocol}))


if __name__=='__main__': main()
