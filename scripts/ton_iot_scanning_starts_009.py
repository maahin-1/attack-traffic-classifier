"""Read only first pcapng packet-header times from the other ZIP members."""
import hashlib
import json
import struct
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
ZIP=ROOT/'data/ton_iot/development/pcaps/normal_scanning.zip'
PLAN=ROOT/'docs/EXPERIMENT-009-SCANNING-METADATA-PLAN.md'
OUT=ROOT/'artifacts/experiment-009-scanning-starts.json'


def first_header(stream):
    header=stream.read(8); bom=stream.read(4)
    magic=header[:4]
    if magic in (b'\xd4\xc3\xb2\xa1',b'\xa1\xb2\xc3\xd4',b'\x4d\x3c\xb2\xa1',b'\xa1\xb2\x3c\x4d'):
        endian='<' if magic in (b'\xd4\xc3\xb2\xa1',b'\x4d\x3c\xb2\xa1') else '>'
        complete=header+bom+stream.read(12)
        if len(complete)!=24: raise ValueError('short classic pcap header')
        _,major,minor,_,_,snap,link=struct.unpack(endian+'IHHIIII',complete)
        if (major,minor)!=(2,4): raise ValueError('unsupported classic pcap version')
        packet=stream.read(16)
        if len(packet)!=16: raise ValueError('short classic packet header')
        sec,frac,captured,original=struct.unpack(endian+'IIII',packet)
        resolution=1000000000 if magic in (b'\x4d\x3c\xb2\xa1',b'\xa1\xb2\x3c\x4d') else 1000000
        if frac>=resolution or captured>original or (snap and captured>snap): raise ValueError('bad classic packet header')
        return {'first_packet_utc_interpretation':datetime.fromtimestamp(sec,timezone.utc).isoformat(),
                'link_type':link,'captured_length':captured,'original_length':original}
    if header[:4]!=b'\x0a\x0d\x0d\x0a' or bom not in (b'\x4d\x3c\x2b\x1a',b'\x1a\x2b\x3c\x4d'): raise ValueError('not supported pcapng')
    endian='<' if bom==b'\x4d\x3c\x2b\x1a' else '>'
    length=struct.unpack(endian+'I',header[4:])[0]
    if length<28 or length%4 or length>65536: raise ValueError('bad section length')
    section=bom+stream.read(length-12)
    if len(section)!=length-8 or struct.unpack(endian+'I',section[-4:])[0]!=length: raise ValueError('section trailer')
    interfaces=[]
    while True:
        h=stream.read(8)
        if len(h)!=8: raise ValueError('no enhanced packet')
        kind,size=struct.unpack(endian+'II',h)
        if size<12 or size%4 or size>64*1024*1024: raise ValueError('block length')
        if kind==6:
            packet_header=stream.read(20)
            if len(packet_header)!=20: raise ValueError('short packet header')
            i,high,low,captured,original=struct.unpack(endian+'IIIII',packet_header)
            if i>=len(interfaces): raise ValueError('unknown interface')
            link,resolution,offset=interfaces[i]
            return {'first_packet_utc_interpretation':datetime.fromtimestamp(((high<<32)|low)//resolution+offset,timezone.utc).isoformat(),
                    'link_type':link, 'captured_length':captured, 'original_length':original}
        if kind in (2,3): raise ValueError('unsupported packet block before first enhanced packet')
        body=stream.read(size-8)
        if len(body)!=size-8 or struct.unpack(endian+'I',body[-4:])[0]!=size: raise ValueError('bad block trailer')
        if kind==1:
            data=body[:-4]
            if len(data)<8: raise ValueError('short interface')
            link=struct.unpack_from(endian+'H',data)[0]; resolution=1000000; offset=0; pos=8
            while pos+4<=len(data):
                code,n=struct.unpack_from(endian+'HH',data,pos); pos+=4
                if not code: break
                if pos+n>len(data): raise ValueError('bad option')
                value=data[pos:pos+n]; pos+=(n+3)&~3
                if code==9:
                    if n!=1: raise ValueError('bad time resolution')
                    resolution=(2**(value[0]&127)) if value[0]&128 else 10**value[0]
                if code==14:
                    if n!=8: raise ValueError('bad time offset')
                    offset=struct.unpack(endian+'q',value)[0]
            interfaces.append((link,resolution,offset))


if __name__=='__main__':
    if OUT.exists(): raise FileExistsError(OUT)
    items=[]
    with zipfile.ZipFile(ZIP) as z:
        for i in range(1,6):
            name=f'normal_scanning/normal_scanning{i}.pcap'; info=z.getinfo(name)
            with z.open(info) as stream: result=first_header(stream)
            items.append({'member':name,'uncompressed_bytes':info.file_size,**result})
    output={'scope':'first timestamped packet header only; no payload, CSV labels, model scores, or CRC verification',
            'plan_sha256':hashlib.sha256(PLAN.read_bytes()).hexdigest(),'files':items}
    OUT.write_text(json.dumps(output,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(output,indent=2))
