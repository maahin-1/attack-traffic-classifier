"""Prepare a traceable local CSV flow reference for a future PCAP comparison."""
import csv
import io
import json
import zipfile
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from attack_traffic.experiment007_input import ALIASES, ARCHIVES, sha256
from attack_traffic.prepare import FEATURES
from attack_traffic.support_extract import feature_digest
from scripts.assess_experiment007 import write_json

SOURCE = ROOT / 'data/cicddos2019' / ARCHIVES['assessment'][0]
OUT = ROOT / 'artifacts/experiment-008-packet-probe'
MEMBER = '03-11/UDPLag.csv'
DIGEST = '7f6878da00b2931ae4427e1984698884a011aa2d39452d724f1ce62a6d1d46d5'


def main():
    if sha256(SOURCE) != ARCHIVES['assessment'][1]:
        raise ValueError('Source archive hash mismatch')
    OUT.mkdir(parents=True, exist_ok=False)
    protocol = {'source_sha256': ARCHIVES['assessment'][1], 'member': MEMBER, 'feature_digest': DIGEST,
                'selection': 'earliest Syn-labeled matching group row in 11:29:00–11:30:25 source clock',
                'purpose': 'locate a packet-level example; no model tuning',
                'clock_note': 'CSV-to-PCAP timezone offset is unverified; do not assume a fixed offset',
                'runner_sha256': sha256(Path(__file__))}
    write_json(OUT / 'protocol.json', protocol)
    first = None; matches = 0
    with zipfile.ZipFile(SOURCE) as zf, zf.open(MEMBER) as raw, io.TextIOWrapper(raw, encoding='utf-8-sig', newline='') as text:
        reader = csv.reader(text)
        headers = [x.strip() for x in next(reader)]
        if len(headers) != 88 or len(set(headers)) != 88:
            raise ValueError('Unexpected source header')
        fi = [headers.index(ALIASES.get(name, name)) for name in FEATURES]
        names = ['Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol', 'Timestamp',
                 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'SYN Flag Count', 'ACK Flag Count', 'Label']
        index = {name: headers.index(name) for name in names}
        for line, row in enumerate(reader, 2):
            if len(row) != len(headers):
                raise ValueError(f'Malformed source row {line}')
            stamp = row[index['Timestamp']].strip()
            if row[index['Label']].strip() != 'Syn' or not ('2018-11-03 11:29:00' <= stamp < '2018-11-03 11:30:26'):
                continue
            values = [float(row[i]) for i in fi]
            if feature_digest(values) != DIGEST:
                continue
            matches += 1
            if first is None or stamp < first['fields']['Timestamp']:
                first = {'record_number': line, 'fields': {name: row[i].strip() for name, i in index.items()}, 'feature_digest': DIGEST}
    if first is None:
        raise ValueError('No matching source row in selected time window')
    if sha256(SOURCE) != protocol['source_sha256'] or sha256(Path(__file__)) != protocol['runner_sha256']:
        raise ValueError('Source or code changed during probe preparation')
    write_json(OUT / 'targets.json', {'status': 'ready_for_pcap', 'source_archive': SOURCE.name, 'member': MEMBER,
                                      'matching_rows_in_window': matches, 'target': first,
                                      'protocol_sha256': sha256(OUT / 'protocol.json')})
    print('Packet probe target prepared:', MEMBER, 'record', first['record_number'], 'dataset clock', first['fields']['Timestamp'], 'matching rows', matches)


if __name__ == '__main__':
    main()
