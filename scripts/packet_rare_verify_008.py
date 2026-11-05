"""Independent byte-level recheck of the previously identified rare packet times."""
import csv
import hashlib
import io
import json
import struct
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PCAP = ROOT/'data/cicddos2019/pcaps/PCAP-03-11.zip'
CSV = ROOT/'data/cicddos2019/CSV-03-11.zip'
OUT = ROOT/'artifacts/experiment-008-rare-flag-verification.json'
TIMES = {1541274410527385, 1541274410527388}


def main():
    packet_results = []; member_hash = hashlib.sha256()
    with zipfile.ZipFile(PCAP) as archive, archive.open('SAT-03-11-2018_0145') as raw:
        def read(n):
            b = raw.read(n); member_hash.update(b); return b
        if read(24)[:4] != b'\xd4\xc3\xb2\xa1':
            raise ValueError('unexpected PCAP')
        while h := read(16):
            if len(h) != 16:
                break
            sec, micros, captured, original = struct.unpack('<IIII', h)
            frame = read(captured)
            if len(frame) != captured:
                break
            stamp = sec*1000000+micros
            if stamp not in TIMES:
                continue
            if frame[12:14] != b'\x08\x00' or frame[14] >> 4 != 4 or frame[23] != 6:
                raise ValueError('expected untagged Ethernet IPv4 TCP')
            tcp = 14 + (frame[14] & 15)*4
            if len(frame) < tcp + 20:
                raise ValueError('truncated TCP header')
            flags = frame[tcp + 13]
            packet_results.append({'time_us':stamp, 'flags_byte':flags, 'syn':bool(flags&2), 'ece':bool(flags&64), 'cwr':bool(flags&128)})
    if member_hash.hexdigest() != 'eef2069b39526d1850e72140424b3b4910b11c8085dafbad85ed4fccd52bb749' or len(packet_results)!=2:
        raise ValueError('member hash or packet count mismatch')
    with zipfile.ZipFile(CSV) as archive, archive.open('03-11/Syn.csv') as raw, io.TextIOWrapper(raw, encoding='utf-8-sig', newline='') as stream:
        reader = csv.reader(stream); headers = [h.strip() for h in next(reader)]
        target = next(row for number, row in enumerate(reader, 2) if number == 509818)
        fields = ['Timestamp','Flow Duration','Total Fwd Packets','Total Backward Packets','SYN Flag Count','ACK Flag Count','URG Flag Count','ECE Flag Count','CWE Flag Count']
        selected = {name:target[headers.index(name)].strip() for name in fields}
    if OUT.exists():
        raise FileExistsError(OUT)
    OUT.write_text(json.dumps({'packet_byte_verification':packet_results, 'csv_record':509818, 'csv_fields':selected,
                               'capture_member_sha256':member_hash.hexdigest(), 'note':'Independent byte and CSV row read, not an independent clock source.'}, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({'packets_verified':len(packet_results), 'csv_record_verified':509818}))


if __name__ == '__main__':
    main()
