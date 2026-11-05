"""Inventory TCP flag bits in three predeclared PCAP members without extraction."""
import hashlib
import json
import struct
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from attack_traffic.experiment007_input import sha256
from scripts.assess_experiment007 import write_json
from scripts.packet_sample_probe_008 import tcp_tuple_and_flags

SOURCE=ROOT/'data/cicddos2019/pcaps/PCAP-03-11.zip'
EXPECTED='cdc8935296cab7a2354d4fd32939f7d5e6c592371e5fb89d6a3094cc05dc38c5'
PLAN=ROOT/'docs/EXPERIMENT-008-ADDITIONAL-PCAP-PLAN.md'
OUT=ROOT/'artifacts/experiment-008-pcap-multi-inventory-v2'
MEMBERS=('SAT-03-11-2018_0','SAT-03-11-2018_0138','SAT-03-11-2018_0145')
FLAGS={'FIN':1,'SYN':2,'RST':4,'PSH':8,'ACK':16,'URG':32,'ECE':64,'CWR':128}


class HashedReader:
    def __init__(self,stream): self.stream=stream; self.digest=hashlib.sha256(); self.bytes=0
    def read(self,n):
        data=self.stream.read(n); self.digest.update(data); self.bytes+=len(data); return data


def timestamp(value):
    sec,micro=value
    return datetime.fromtimestamp(sec,timezone.utc).replace(microsecond=micro).isoformat()


def scan(stream):
    h=stream.read(24)
    if len(h)!=24 or h[:4]!=bytes.fromhex('d4c3b2a1'): raise ValueError('Unsupported PCAP format')
    major,minor,_,_,snaplen,linktype=struct.unpack('<HHiIII',h[4:])
    if (major,minor)!=(2,4) or linktype!=1 or not 0<snaplen<=16*1024*1024: raise ValueError('Unsupported PCAP header')
    packets=tcp=0; flag_counts=dict.fromkeys(FLAGS,0); combinations={}; first=last=None; rare={}; truncation=None
    while True:
        h=stream.read(16)
        if not h: break
        if len(h)!=16:
            truncation={'kind':'packet_header','bytes_available':len(h),'bytes_expected':16}
            break
        sec,micro,size,original=struct.unpack('<IIII',h)
        if micro>=1000000 or size>original or size>snaplen: raise ValueError('Invalid packet record')
        frame=stream.read(size)
        if len(frame)!=size:
            truncation={'kind':'packet_data','bytes_available':len(frame),'bytes_expected':size}
            break
        packets+=1; point=(sec,micro); first=point if first is None or point<first else first; last=point if last is None or point>last else last
        decoded=tcp_tuple_and_flags(frame)
        if decoded is None: continue
        tcp+=1; mask=decoded[1]; combinations[str(mask)]=combinations.get(str(mask),0)+1
        for name,bit in FLAGS.items():
            if mask&bit:
                flag_counts[name]+=1
                if name in ('URG','ECE','CWR') and name not in rare: rare[name]=timestamp(point)
    return {'packets':packets,'parseable_ipv4_tcp_packets':tcp,'flag_packet_counts':flag_counts,
            'flag_mask_counts':combinations,'first_packet_utc':timestamp(first) if first else None,
            'last_packet_utc':timestamp(last) if last else None,'first_rare_flag_utc':rare,
            'truncated_final_record':truncation}


def main():
    if sha256(SOURCE)!=EXPECTED: raise ValueError('Source archive hash mismatch')
    dependencies=[Path(__file__),PLAN,ROOT/'scripts/packet_sample_probe_008.py']
    hashes={p.relative_to(ROOT).as_posix():sha256(p) for p in dependencies}
    OUT.mkdir(parents=True,exist_ok=False)
    protocol={'source_sha256':EXPECTED,'members':MEMBERS,'dependencies':hashes,
              'selection':'first segment, adjacent segment after 0137, final segment; post-hoc convenience inventory',
              'scope':'parseable IPv4 TCP packet bits, not matched source flows or labels'}
    write_json(OUT/'protocol.json',protocol)
    results={}
    try:
        with zipfile.ZipFile(SOURCE) as z:
            for name in MEMBERS:
                info=z.getinfo(name)
                with z.open(info) as raw:
                    stream=HashedReader(raw); result=scan(stream)
                    if stream.bytes!=info.file_size: raise ValueError('ZIP member length mismatch')
                    result.update({'uncompressed_bytes':stream.bytes,'uncompressed_sha256':stream.digest.hexdigest(),
                                   'zip_crc32':f'{info.CRC:08x}','zip_crc_verified':True})
                    results[name]=result
                write_json(OUT/'progress.json',{'status':'running','completed_members':list(results)})
        if sha256(SOURCE)!=EXPECTED or any(sha256(ROOT/p)!=h for p,h in hashes.items()): raise ValueError('Input changed during scan')
        report={'status':'complete','members':results,'protocol_sha256':sha256(OUT/'protocol.json')}
        write_json(OUT/'report.json',report); write_json(OUT/'progress.json',{'status':'complete','completed_members':list(results)})
        print(json.dumps({n:r['flag_packet_counts'] for n,r in results.items()}))
    except BaseException as exc:
        write_json(OUT/'progress.json',{'status':'failed','completed_members':list(results),'error':repr(exc)})
        raise


if __name__=='__main__': main()
