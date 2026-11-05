"""Aggregate Linux cooked header statistics and bounded payload heuristics."""
import hashlib
import json
import struct
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts.ton_iot_scanning_probe_009 import sha

SOURCE=ROOT/'data/ton_iot/development/normal/normal_13.pcap'
BASE=ROOT/'artifacts/experiment-009-normal13-protocol/report.json'
PLAN=ROOT/'docs/EXPERIMENT-009-NORMAL13-SLL-PLAN.md'
OUT=ROOT/'artifacts/experiment-009-normal13-sll'


def candidate_offsets(payload):
    """Only plausibility with complete checksummed IPv4 header; no port validation."""
    found=[]
    for i in range(min(65,max(0,len(payload)-19))):
        if payload[i]>>4!=4:continue
        ihl=(payload[i]&15)*4
        if ihl<20 or i+ihl>len(payload) or payload[i+9] not in (6,17):continue
        if int.from_bytes(payload[i+2:i+4],'big')<ihl+4:continue
        total=sum(struct.unpack('!'+str(ihl//2)+'H',payload[i:i+ihl]))
        total=(total&65535)+(total>>16); total=(total&65535)+(total>>16)
        if total==65535:found.append(i)
    return found


def main():
    if OUT.exists():raise FileExistsError(OUT)
    base=json.loads(BASE.read_text()); expected=base['source_sha256']
    if sha(SOURCE)!=expected:raise ValueError('source hash mismatch')
    deps=[Path(__file__),PLAN,BASE]; hashes={p.relative_to(ROOT).as_posix():sha(p) for p in deps}
    OUT.mkdir(parents=True)
    (OUT/'protocol.json').write_text(json.dumps({'source_sha256':expected,'dependencies':hashes,'sample':'every 160th 0x0003 frame by file order','offsets':list(range(65))},indent=2)+'\n',encoding='utf-8')
    stats=Counter(); headers=Counter(); hours=Counter(); lengths=Counter(); sample=Counter(); offsets=Counter(); digest=hashlib.sha256(); interfaces=[]
    with SOURCE.open('rb') as f:
        def read(n):
            data=f.read(n);digest.update(data);return data
        h=read(12)
        if len(h)!=12 or h[:4]!=b'\x0a\x0d\x0d\x0a' or h[8:]!=b'\x4d\x3c\x2b\x1a':raise ValueError('expected little-endian pcapng')
        size=struct.unpack_from('<I',h,4)[0]
        if size<28 or size%4 or size>65536:raise ValueError('bad section')
        rest=read(size-12)
        if len(rest)!=size-12 or struct.unpack('<I',rest[-4:])[0]!=size:raise ValueError('bad section trailer')
        while True:
            h=read(8)
            if not h:break
            if len(h)!=8:raise ValueError('truncated block')
            kind,size=struct.unpack('<II',h)
            if size<12 or size%4 or size>64*1024*1024:raise ValueError('invalid block size')
            b=read(size-8)
            if len(b)!=size-8 or struct.unpack('<I',b[-4:])[0]!=size:raise ValueError('bad trailer')
            data=b[:-4]
            if kind==1:
                if len(data)<8:raise ValueError('short interface')
                interfaces.append(struct.unpack_from('<H',data)[0])
            elif kind==6:
                if len(data)<20:raise ValueError('short packet')
                index,hi,lo,cap,orig=struct.unpack_from('<IIIII',data)
                if index>=len(interfaces) or cap>orig or len(data)<20+cap:raise ValueError('invalid packet')
                if interfaces[index]!=113:raise ValueError('unexpected interface')
                frame=data[20:20+cap];stats['packets']+=1
                if len(frame)<16:stats['short_cooked_headers']+=1;continue
                packet_type,hardware,addrlen=struct.unpack_from('!HHH',frame)
                if frame[14:16]!=b'\x00\x03':continue
                stats['unknown_0003']+=1
                headers[f'packet_{packet_type}_hardware_{hardware}_addresslen_{addrlen}']+=1
                lengths['captured_equals_original' if cap==orig else 'capture_truncated']+=1
                second=((hi<<32)|lo)//1000000
                hours[datetime.fromtimestamp(second,timezone.utc).strftime('%Y-%m-%dT%H:00Z')]+=1
                if stats['unknown_0003']%160:continue
                sample['sampled_frames']+=1;payload=frame[16:]
                if not payload:sample['empty_payload']+=1;continue
                sample['first_nibble_'+str(payload[0]>>4)]+=1
                if len(payload)>=14 and int.from_bytes(payload[12:14],'big') in (0x0800,0x86dd,0x0806):sample['common_ethernet_type_candidate']+=1
                matches=candidate_offsets(payload)
                if matches:sample['checksum_valid_ipv4_candidate_frames']+=1;offsets.update(str(i) for i in matches)
            elif kind in (2,3,0x0a0d0d0a):raise ValueError('unsupported packet block or extra section')
    if digest.hexdigest()!=expected or sha(SOURCE)!=expected or any(sha(ROOT/p)!=h for p,h in hashes.items()):raise ValueError('source changed')
    if stats['packets']!=base['packet_counts']['packets'] or stats['unknown_0003']!=base['network_layer']['ethertype_0x0003']:raise ValueError('earlier counts not reproduced')
    report={'status':'complete','packet_totals':dict(stats),'cooked_header_combinations':dict(headers),'captured_lengths':dict(lengths),
            'unknown_0003_packets_per_utc_hour':dict(hours),'sample_heuristics':dict(sample),'ipv4_candidate_offsets':dict(offsets),
            'source_sha256':expected,'protocol_sha256':sha(OUT/'protocol.json')}
    (OUT/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    print(json.dumps(report))


if __name__=='__main__':main()
