"""Development-only pcapng and source-event compatibility probe."""
import csv
import hashlib
import ipaddress
import json
import struct
import sys
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT/'data/ton_iot/development/pcaps/normal_scanning.zip'
CSV = ROOT/'data/ton_iot/development/metadata/GroundTruth_Network_1.csv'
MEMBER = 'normal_scanning/normal_scanning6.pcap'
EXPECTED_CSV = '79f2d99bf34965126480bc2f18949b67f7fc0a26c135c24a88f9aae700913f28'
PLAN = ROOT/'docs/EXPERIMENT-009-SCANNING6-PROBE-PLAN.md'
OUT = ROOT/'artifacts/experiment-009-scanning6-probe-v2'


def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''): h.update(block)
    return h.hexdigest()


def parse_options(raw, endian):
    options={}; offset=0
    while offset+4<=len(raw):
        code,length=struct.unpack_from(endian+'HH',raw,offset); offset+=4
        if code==0: break
        if offset+length>len(raw): raise ValueError('Truncated pcapng option')
        options[code]=raw[offset:offset+length]; offset+=(length+3)&~3
    return options


def decode(frame, linktype):
    """Return directional IPv4 tuple and protocol, or None for unsupported frames."""
    if linktype==113:
        if len(frame)<16: return None
        offset=16; ethertype=int.from_bytes(frame[14:16],'big')
    elif linktype==1:
        if len(frame)<14: return None
        offset=14; ethertype=int.from_bytes(frame[12:14],'big')
    else: return None
    for _ in range(4):
        if ethertype not in (0x8100,0x88a8,0x9100): break
        if len(frame)<offset+4: return None
        ethertype=int.from_bytes(frame[offset+2:offset+4],'big'); offset+=4
    if ethertype!=0x0800 or len(frame)<offset+20 or frame[offset]>>4!=4: return None
    ihl=(frame[offset]&15)*4
    if ihl<20 or len(frame)<offset+ihl+4 or int.from_bytes(frame[offset+2:offset+4],'big')<ihl+4 or int.from_bytes(frame[offset+6:offset+8],'big')&0x1fff: return None
    proto=frame[offset+9]
    if proto not in (6,17): return None
    src=frame[offset+12:offset+16]; dst=frame[offset+16:offset+20]
    sport,dport=struct.unpack_from('!HH',frame,offset+ihl)
    return (proto,src,sport,dst,dport)


def iter_packets(stream, stats):
    endian=None; interfaces=[]
    while True:
        header=stream.read(8)
        if not header: return
        if len(header)!=8: raise ValueError('Truncated pcapng block header')
        if header[:4]==b'\x0a\x0d\x0d\x0a':
            bom=stream.read(4)
            if bom==b'\x4d\x3c\x2b\x1a': endian='<'
            elif bom==b'\x1a\x2b\x3c\x4d': endian='>'
            else: raise ValueError('Invalid section byte order')
            length=struct.unpack(endian+'I',header[4:])[0]
            if length<28 or length%4 or length>64*1024*1024: raise ValueError('Invalid section length')
            rest=stream.read(length-12)
            if len(rest)!=length-12 or struct.unpack(endian+'I',rest[-4:])[0]!=length: raise ValueError('Bad section trailer')
            interfaces=[]; stats['sections']+=1; continue
        if endian is None: raise ValueError('No pcapng section header')
        block_type,length=struct.unpack(endian+'II',header)
        if length<12 or length%4 or length>64*1024*1024: raise ValueError('Invalid block size')
        body=stream.read(length-8)
        if len(body)!=length-8 or struct.unpack(endian+'I',body[-4:])[0]!=length: raise ValueError('Bad block trailer')
        data=body[:-4]; stats['blocks']+=1
        if block_type==1:
            if len(data)<8: raise ValueError('Short interface block')
            link,_,snap=struct.unpack_from(endian+'HHI',data)
            opts=parse_options(data[8:],endian); raw=opts.get(9,b'\x06')
            if len(raw)!=1: raise ValueError('Invalid timestamp resolution')
            val=raw[0]; resolution=(2**(val&127)) if val&128 else (10**val)
            offset=struct.unpack(endian+'q',opts[14])[0] if 14 in opts and len(opts[14])==8 else 0
            if 14 in opts and len(opts[14])!=8: raise ValueError('Invalid timestamp offset')
            interfaces.append((link,snap,resolution,offset)); stats[f'interface_{link}_ticks_{resolution}_offset_{offset}']+=1
        elif block_type==6:
            if len(data)<20: raise ValueError('Short enhanced packet block')
            i,high,low,cap,orig=struct.unpack_from(endian+'IIIII',data)
            if i>=len(interfaces): raise ValueError('Unknown interface')
            link,snap,resolution,offset=interfaces[i]
            if cap>orig or (snap and cap>snap) or len(data)<20+cap: raise ValueError('Invalid packet size')
            second=((high<<32)|low)//resolution+offset
            stats['packets']+=1
            yield second,decode(data[20:20+cap],link)
        elif block_type in (2,3):
            stats['unsupported_packet_blocks']+=1


def iso(seconds): return datetime.fromtimestamp(seconds,timezone.utc).isoformat()


def write(path,value): path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n',encoding='utf-8')


def main():
    if sha(CSV)!=EXPECTED_CSV: raise ValueError('CSV hash mismatch')
    archive_hash=sha(ARCHIVE); deps={str(p.relative_to(ROOT)):sha(p) for p in (Path(__file__),PLAN)}
    OUT.mkdir(parents=True,exist_ok=False)
    protocol={'zip_sha256':archive_hash,'csv_sha256':EXPECTED_CSV,'dependencies':deps,'member':MEMBER,'max_selected_unique_keys':50000,
              'matching':'exact epoch second and TCP/UDP directional IPv4 tuple; reverse separately','label_policy':'descriptive source events only'}
    write(OUT/'protocol.json',protocol)
    counters=Counter(); low=high=None; protocols=Counter(); skipped=0
    with zipfile.ZipFile(ARCHIVE) as archive:
        info=archive.getinfo(MEMBER); member_digest=hashlib.sha256()
        class Reader:
            def __init__(self,stream): self.stream=stream
            def read(self,n):
                data=self.stream.read(n); member_digest.update(data); return data
        with archive.open(info) as raw:
            for second,key in iter_packets(Reader(raw),counters):
                low=second if low is None else min(low,second); high=second if high is None else max(high,second)
                if key is None: skipped+=1
                else: protocols['tcp' if key[0]==6 else 'udp']+=1
    if low is None: raise ValueError('No timestamped packets')
    write(OUT/'progress.json',{'phase':'pcap_inventory_complete','packets':counters['packets']})
    selected=set(); all_types=Counter(); all_proto=Counter(); widths=Counter(); csv_low=csv_high=None; eligible_rows=duplicates=invalid=unsupported=0; rows=0
    with CSV.open(encoding='utf-8-sig',newline='') as f:
        reader=csv.reader(f); header=next(reader)
        if header!=['ts','src_ip','src_port','dst_ip','dst_port','proto','type']: raise ValueError('Unexpected CSV schema')
        for row in reader:
            rows+=1; widths[len(row)]+=1
            if len(row)!=7: invalid+=1; continue
            all_types[row[6]]+=1; all_proto[row[5]]+=1
            try:
                second=int(row[0])
            except ValueError: invalid+=1; continue
            csv_low=second if csv_low is None else min(csv_low,second); csv_high=second if csv_high is None else max(csv_high,second)
            if row[5].lower() not in ('tcp','udp'):
                unsupported+=1; continue
            try:
                proto={'tcp':6,'udp':17}[row[5].lower()]
                key=(second,proto,ipaddress.IPv4Address(row[1]).packed,int(row[2]),ipaddress.IPv4Address(row[3]).packed,int(row[4]))
                if not 0<=key[3]<=65535 or not 0<=key[5]<=65535: raise ValueError('port')
            except (ValueError,KeyError): invalid+=1; continue
            if low<=second<=high:
                eligible_rows+=1
                if key in selected: duplicates+=1
                elif len(selected)<50000: selected.add(key)
    match=set(); reverse=set(); matching_packets=0; counters2=Counter(); hash2=hashlib.sha256()
    if selected:
        class Reader2:
            def __init__(self,stream): self.stream=stream
            def read(self,n):
                data=self.stream.read(n); hash2.update(data); return data
        with zipfile.ZipFile(ARCHIVE) as archive,archive.open(MEMBER) as raw:
            for second,key in iter_packets(Reader2(raw),counters2):
                if key is None: continue
                p,src,sp,dst,dp=key; direct=(second,p,src,sp,dst,dp); rev=(second,p,dst,dp,src,sp)
                if direct in selected: match.add(direct); matching_packets+=1
                if rev in selected: reverse.add(rev)
        if hash2.hexdigest()!=member_digest.hexdigest(): raise ValueError('Member changed between passes')
    if sha(CSV)!=EXPECTED_CSV or sha(ARCHIVE)!=archive_hash or any(sha(ROOT/p)!=h for p,h in deps.items()): raise ValueError('Input changed during run')
    report={'status':'complete','pcap':{'member':MEMBER,'member_bytes':info.file_size,'member_sha256':member_digest.hexdigest(),
            'zip_member_crc32':f'{info.CRC:08x}','zip_crc_verified':True,'stats':dict(counters),'decodable_protocols':dict(protocols),
            'unsupported_or_other_packets':skipped,'first_second_utc_interpretation':iso(low),'last_second_utc_interpretation':iso(high)},
            'csv':{'rows':rows,'widths':dict(widths),'type_counts':dict(all_types),'protocol_counts':dict(all_proto),'invalid_rows':invalid,'unsupported_transport_rows':unsupported,
                   'first_second_utc_interpretation':iso(csv_low) if csv_low is not None else None,
                   'last_second_utc_interpretation':iso(csv_high) if csv_high is not None else None,
                   'rows_in_pcap_range':eligible_rows,'duplicate_selected_keys_in_range':duplicates,'selected_unique_keys':len(selected)},
            'match':{'exact_direction_selected_keys':len(match),'reverse_direction_selected_keys':len(reverse),
                     'unmatched_either_direction':len(selected-len_union(match,reverse)), 'exact_direction_matching_packets':matching_packets},
            'protocol_sha256':sha(OUT/'protocol.json')}
    write(OUT/'report.json',report); write(OUT/'progress.json',{'phase':'complete'})
    print(json.dumps({'pcap_packets':counters['packets'],'csv_rows':rows,'selected':len(selected),'direct_matches':len(match),'reverse_matches':len(reverse)}))


def len_union(a,b): return a|b


if __name__=='__main__': main()
