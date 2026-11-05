"""Post-hoc aggregate network protocol inventory for the normal13 capture."""
import hashlib
import json
import struct
import sys
from collections import Counter
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts.ton_iot_scanning_probe_009 import decode, sha

PCAP=ROOT/'data/ton_iot/development/normal/normal_13.pcap'
BASE=ROOT/'artifacts/experiment-009-normal13-inventory/report.json'
PLAN=ROOT/'docs/EXPERIMENT-009-NORMAL13-PROTOCOL-PLAN.md'
OUT=ROOT/'artifacts/experiment-009-normal13-protocol'


def classify(frame,link):
    if link==113:
        if len(frame)<16:return 'truncated_link',None,False
        offset=16; ethertype=int.from_bytes(frame[14:16],'big')
    elif link==1:
        if len(frame)<14:return 'truncated_link',None,False
        offset=14; ethertype=int.from_bytes(frame[12:14],'big')
    else:return 'unsupported_link',None,False
    for _ in range(4):
        if ethertype not in (0x8100,0x88a8,0x9100):break
        if len(frame)<offset+4:return 'truncated_vlan',None,False
        ethertype=int.from_bytes(frame[offset+2:offset+4],'big');offset+=4
    if ethertype!=0x0800:return f'ethertype_0x{ethertype:04x}',None,False
    if len(frame)<offset+20 or frame[offset]>>4!=4 or (frame[offset]&15)<5:return 'malformed_ipv4',None,False
    protocol=frame[offset+9]; fragment=bool(int.from_bytes(frame[offset+6:offset+8],'big')&0x1fff)
    return 'ipv4',protocol,fragment


def main():
    if OUT.exists():raise FileExistsError(OUT)
    base=json.loads(BASE.read_text()); source_hash=base['source_sha256']
    if sha(PCAP)!=source_hash:raise ValueError('source hash mismatch')
    deps=[Path(__file__),PLAN,ROOT/'scripts/ton_iot_scanning_probe_009.py',BASE]
    hashes={p.relative_to(ROOT).as_posix():sha(p) for p in deps}
    OUT.mkdir(parents=True)
    (OUT/'protocol.json').write_text(json.dumps({'source_sha256':source_hash,'dependencies':hashes,'scope':'aggregate header classifications only'},indent=2)+'\n',encoding='utf-8')
    stats=Counter();layers=Counter();ip_protocols=Counter();decode_counts=Counter();frag=0;interfaces=[];digest=hashlib.sha256()
    with PCAP.open('rb') as f:
        def read(n):
            data=f.read(n);digest.update(data);return data
        h=read(12)
        if len(h)!=12 or h[:4]!=b'\x0a\x0d\x0d\x0a' or h[8:]!=b'\x4d\x3c\x2b\x1a':raise ValueError('unsupported pcapng')
        length=struct.unpack_from('<I',h,4)[0]
        if length<28 or length%4 or length>65536:raise ValueError('invalid section length')
        section=read(length-12)
        if len(section)!=length-12 or struct.unpack('<I',section[-4:])[0]!=length:raise ValueError('invalid section trailer')
        while True:
            h=read(8)
            if not h:break
            if len(h)!=8:raise ValueError('truncated block header')
            kind,length=struct.unpack('<II',h)
            if length<12 or length%4 or length>64*1024*1024:raise ValueError('invalid block size')
            b=read(length-8)
            if len(b)!=length-8 or struct.unpack('<I',b[-4:])[0]!=length:raise ValueError('invalid block trailer')
            data=b[:-4]
            if kind==1:
                if len(data)<8:raise ValueError('truncated interface')
                interfaces.append(struct.unpack_from('<H',data)[0])
            elif kind==6:
                if len(data)<20:raise ValueError('truncated packet header')
                index,_,_,cap,orig=struct.unpack_from('<IIIII',data)
                if index>=len(interfaces) or cap>orig or len(data)<20+cap:raise ValueError('invalid packet')
                frame=data[20:20+cap]; link=interfaces[index]; stats['packets']+=1
                category,proto,fragment=classify(frame,link); layers[category]+=1
                if proto is not None:ip_protocols[str(proto)]+=1
                frag+=fragment
                decoded=decode(frame,link)
                decode_counts['other_or_unsupported' if decoded is None else 'tcp' if decoded[0]==6 else 'udp']+=1
            elif kind in (2,3):stats['unsupported_packet_blocks']+=1
            elif kind==0x0a0d0d0a:raise ValueError('multiple sections not supported by diagnostic')
    if digest.hexdigest()!=source_hash or sha(PCAP)!=source_hash or any(sha(ROOT/k)!=v for k,v in hashes.items()):raise ValueError('source changed')
    if stats['packets']!=base['packet_stats']['packets'] or dict(decode_counts)!=base['transport']:raise ValueError('prior packet inventory not reproduced')
    result={'status':'complete','packet_counts':dict(stats),'network_layer':dict(layers),'ipv4_protocol_numbers':dict(ip_protocols),
            'noninitial_ipv4_fragments':frag,'existing_decoder_categories':dict(decode_counts),'source_sha256':source_hash,
            'protocol_sha256':sha(OUT/'protocol.json')}
    (OUT/'report.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    print(json.dumps(result))


if __name__=='__main__':main()
