"""Run the predeclared scanning1 probe, supporting classic and pcapng headers."""
import hashlib
import struct
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import scripts.ton_iot_scanning_probe_009 as probe
original_packets=probe.iter_packets


class PrefixReader:
    def __init__(self,prefix,source): self.prefix=prefix; self.source=source
    def read(self,n):
        if not self.prefix: return self.source.read(n)
        head,self.prefix=self.prefix[:n],self.prefix[n:]
        return head+self.source.read(n-len(head)) if len(head)<n else head


def packets(stream,stats):
    magic=stream.read(4); reader=PrefixReader(magic,stream)
    if magic==b'\x0a\x0d\x0d\x0a':
        yield from original_packets(reader,stats); return
    formats={b'\xd4\xc3\xb2\xa1':('<',1000000),b'\xa1\xb2\xc3\xd4':('>',1000000),
             b'\x4d\x3c\xb2\xa1':('<',1000000000),b'\xa1\xb2\x3c\x4d':('>',1000000000)}
    if magic not in formats: raise ValueError('unsupported pcap format')
    endian,resolution=formats[magic]; header=reader.read(24)
    if len(header)!=24: raise ValueError('truncated pcap header')
    _,major,minor,_,_,snap,link=struct.unpack(endian+'IHHIIII',header)
    if (major,minor)!=(2,4): raise ValueError('unsupported pcap version')
    stats['sections']+=1; stats[f'interface_{link}_ticks_{resolution}_offset_0']+=1
    while True:
        header=reader.read(16)
        if not header: return
        if len(header)!=16: raise ValueError('truncated packet header')
        sec,frac,cap,orig=struct.unpack(endian+'IIII',header)
        if frac>=resolution or cap>orig or (snap and cap>snap) or cap>64*1024*1024: raise ValueError('invalid packet header')
        frame=reader.read(cap)
        if len(frame)!=cap: raise ValueError('truncated packet')
        stats['packets']+=1
        yield sec,probe.decode(frame,link)


if __name__=='__main__':
    original_write=probe.write
    runner_hash=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    probe.MEMBER='normal_scanning/normal_scanning1.pcap'
    probe.PLAN=ROOT/'docs/EXPERIMENT-009-SCANNING1-PROBE-PLAN.md'
    probe.OUT=ROOT/'artifacts/experiment-009-scanning1-probe'
    probe.iter_packets=packets
    def write_with_runner(path,value):
        if path.name=='protocol.json': value['runner_sha256']=runner_hash
        return original_write(path,value)
    probe.write=write_with_runner
    probe.main()
    if hashlib.sha256(Path(__file__).read_bytes()).hexdigest()!=runner_hash: raise ValueError('Runner changed during probe')
