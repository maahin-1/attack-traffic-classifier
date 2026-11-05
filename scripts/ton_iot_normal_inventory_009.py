"""Inventory the provided development capture without exporting endpoints."""
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts.ton_iot_scanning_probe_009 import sha
from scripts.ton_iot_scanning1_probe_009 import packets

PCAP=ROOT/'data/ton_iot/development/normal/normal_13.pcap'
PLAN=ROOT/'docs/EXPERIMENT-009-NORMAL13-INVENTORY-PLAN.md'
OUT=ROOT/'artifacts/experiment-009-normal13-inventory'


def iso(second): return datetime.fromtimestamp(second,timezone.utc).isoformat()


def main():
    if not PCAP.is_file(): raise FileNotFoundError(PCAP)
    if OUT.exists(): raise FileExistsError(OUT)
    before=sha(PCAP); size=PCAP.stat().st_size
    deps=[Path(__file__),PLAN,ROOT/'scripts/ton_iot_scanning_probe_009.py',ROOT/'scripts/ton_iot_scanning1_probe_009.py']
    hashes={p.relative_to(ROOT).as_posix():sha(p) for p in deps}
    OUT.mkdir(parents=True)
    protocol={'source_sha256':before,'source_bytes':size,'dependencies':hashes,
              'scope':'development-only packet-level inventory; source naming is not a verified benign label'}
    (OUT/'protocol.json').write_text(json.dumps(protocol,indent=2)+'\n',encoding='utf-8')
    stats=Counter(); transport=Counter(); hours=Counter(); low=high=None; observed=hashlib.sha256()
    class HashReader:
        def __init__(self,f): self.f=f
        def read(self,n):
            data=self.f.read(n);observed.update(data);return data
    with PCAP.open('rb') as raw:
        for second,key in packets(HashReader(raw),stats):
            low=second if low is None else min(low,second); high=second if high is None else max(high,second)
            hours[datetime.fromtimestamp(second,timezone.utc).strftime('%Y-%m-%dT%H:00Z')]+=1
            transport['other_or_unsupported' if key is None else 'tcp' if key[0]==6 else 'udp']+=1
    if low is None: raise ValueError('no timestamped packets')
    if observed.hexdigest()!=before or sha(PCAP)!=before or any(sha(ROOT/p)!=v for p,v in hashes.items()): raise ValueError('input changed during inventory')
    reference={'csv_events':[1556021410,1556025857],'scanning1':[1556021409,1556025302]}
    overlaps={name:{'ranges_overlap':low<=end and start<=high,'reference_utc':[iso(start),iso(end)]} for name,(start,end) in reference.items()}
    report={'status':'complete','source_bytes':size,'source_sha256':before,'packet_stats':dict(stats),
            'transport':dict(transport),'first_utc_interpretation':iso(low),'last_utc_interpretation':iso(high),
            'packet_counts_per_utc_hour':dict(hours),'time_range_comparisons':overlaps,'benign_status':'unverified',
            'protocol_sha256':sha(OUT/'protocol.json')}
    (OUT/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    print(json.dumps({'packets':stats['packets'],'start':iso(low),'end':iso(high),'transport':dict(transport),'overlaps':overlaps}))


if __name__=='__main__': main()
