"""Count observable IPv4 TCP flags in one pinned PCAP segment, without labels."""
import json
import struct
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from attack_traffic.experiment007_input import sha256
from scripts.assess_experiment007 import write_json
from scripts.packet_sample_probe_008 import tcp_tuple_and_flags

PCAP=ROOT/'data/cicddos2019/pcaps/SAT-03-11-2018_0137.pcap'
EXPECTED='e8d76130a6e5014177a9260345495fc48ac667fc31f92782748621cac69c43bc'
OUT=ROOT/'artifacts/experiment-008-pcap-flag-inventory'
FLAGS={'FIN':1,'SYN':2,'RST':4,'PSH':8,'ACK':16,'URG':32,'ECE':64,'CWR':128}


def main():
    if sha256(PCAP)!=EXPECTED: raise ValueError('PCAP hash mismatch')
    dependencies=[Path(__file__),ROOT/'scripts/packet_sample_probe_008.py']
    hashes={p.relative_to(ROOT).as_posix():sha256(p) for p in dependencies}
    OUT.mkdir(parents=True,exist_ok=False)
    protocol={'pcap_sha256':EXPECTED,'dependencies':hashes,'scope':'all parseable IPv4 TCP packets in this segment, not CSV flows or labels',
              'limits':'Ethernet/VLAN; noninitial fragments and truncated or non-TCP headers omitted; no endpoint information'}
    write_json(OUT/'protocol.json',protocol)
    packets=tcp=0; counts=dict.fromkeys(FLAGS,0); combinations={}
    try:
        with PCAP.open('rb') as stream:
            header=stream.read(24)
            if len(header)!=24 or header[:4]!=bytes.fromhex('d4c3b2a1'): raise ValueError('Unexpected PCAP format')
            major,minor,_,_,snaplen,linktype=struct.unpack('<HHiIII',header[4:])
            if (major,minor)!=(2,4) or linktype!=1 or not 0<snaplen<=16*1024*1024: raise ValueError('Unexpected PCAP header')
            while True:
                h=stream.read(16)
                if not h: break
                if len(h)!=16: raise ValueError('Truncated packet header')
                sec,micro,size,original=struct.unpack('<IIII',h)
                if micro>=1000000 or size>original or size>snaplen: raise ValueError('Invalid packet record')
                frame=stream.read(size)
                if len(frame)!=size: raise ValueError('Truncated packet')
                packets+=1; decoded=tcp_tuple_and_flags(frame)
                if decoded is None: continue
                tcp+=1; mask=decoded[1]; combinations[str(mask)]=combinations.get(str(mask),0)+1
                for name,bit in FLAGS.items(): counts[name]+=bool(mask&bit)
        if sha256(PCAP)!=EXPECTED or any(sha256(ROOT/p)!=h for p,h in hashes.items()): raise ValueError('Input changed during scan')
        result={'status':'complete','packets_scanned':packets,'parseable_ipv4_tcp_packets':tcp,'tcp_flag_packet_counts':counts,
                'tcp_flag_mask_counts':combinations,'protocol_sha256':sha256(OUT/'protocol.json')}
        write_json(OUT/'report.json',result); print(json.dumps(result))
    except BaseException as exc:
        write_json(OUT/'failure.json',{'status':'failed','packets_scanned':packets,'error':repr(exc)})
        raise


if __name__=='__main__': main()
