"""Post-hoc flag-column hypotheses for the already matched packet examples."""
import csv
import io
import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from attack_traffic.experiment007_input import ARCHIVES, sha256
from scripts.assess_experiment007 import write_json

SOURCE = ROOT / 'data/cicddos2019' / ARCHIVES['assessment'][0]
STUDY = ROOT / 'artifacts/experiment-008-packet-diverse'
OUT = ROOT / 'artifacts/experiment-008-flag-hypotheses'
MEMBER = '03-11/UDPLag.csv'
CSV_FLAGS = ('FIN','SYN','RST','PSH','ACK','URG','CWE','ECE')
PACKET_FLAGS = {'FIN':1,'SYN':2,'RST':4,'PSH':8,'ACK':16,'URG':32,'CWR':128,'ECE':64}


def correlations(observations):
    result = {}
    for column in CSV_FLAGS:
        positive = sum(item['csv'][column] > 0 for item in observations)
        matches = {name: sum((item['csv'][column] > 0) == bool(item['first_flags'] & bit) for item in observations)
                   for name, bit in PACKET_FLAGS.items()}
        result[column] = {'positive_rows':positive, 'first_packet_agreements':matches}
    return result


def main():
    source_hash = sha256(SOURCE)
    if source_hash != ARCHIVES['assessment'][1]:
        raise ValueError('Source archive hash mismatch')
    report_path, protocol_path = STUDY / 'report.json', STUDY / 'protocol.json'
    report = json.loads(report_path.read_text(encoding='utf-8'))
    if report['status'] != 'complete' or report['protocol_sha256'] != sha256(protocol_path):
        raise ValueError('Completed packet study required')
    selected = {x['record_number']:x for x in report['candidates'] if x['matched_two_forward_packets']}
    if len(selected) != 38:
        raise ValueError('Unexpected matched sample support')
    OUT.mkdir(parents=True, exist_ok=False)
    protocol = {'source_sha256':source_hash, 'packet_study_sha256':sha256(report_path),
                'packet_study_protocol_sha256':sha256(protocol_path), 'script_sha256':sha256(Path(__file__)),
                'scope':'post-hoc equality of binary CSV flag columns and first-packet flags for 38 existing matched examples; no mapping is adopted',
                'source_records':sorted(selected), 'limitations':'convenience sample of one CSV member and one PCAP segment; repeated tuples and missing flag variation limit identification'}
    write_json(OUT / 'protocol.json',protocol)
    observations=[]
    with zipfile.ZipFile(SOURCE) as zf, zf.open(MEMBER) as raw, io.TextIOWrapper(raw,encoding='utf-8-sig',newline='') as stream:
        reader=csv.reader(stream); headers=[x.strip() for x in next(reader)]
        names=[n+' Flag Count' for n in CSV_FLAGS]
        if len(headers)!=88 or len(set(headers))!=88 or any(headers.count(n)!=1 for n in names):
            raise ValueError('Unexpected source schema')
        indices={n:headers.index(n+' Flag Count') for n in CSV_FLAGS}
        label_i,stamp_i=headers.index('Label'),headers.index('Timestamp')
        for number,row in enumerate(reader,2):
            if number not in selected: continue
            item=selected[number]
            if len(row)!=88 or row[label_i].strip()!=item['label'] or row[stamp_i].strip()!=item['csv_clock']:
                raise ValueError('Source record mismatch')
            events=sorted(item['packets_in_window'],key=lambda x:x['offset_us'])
            flags={k:int(float(row[i])) for k,i in indices.items()}
            if any(flags[k] != item['csv_flags'][k] for k in item['csv_flags']):
                raise ValueError('Saved flag fields differ from source')
            observations.append({'record_number':number,'label':item['label'],'csv':flags,'first_flags':events[0]['flags']})
            if len(observations)==len(selected): break
    if len(observations)!=len(selected): raise ValueError('Source records missing')
    for path, key in ((SOURCE,'source_sha256'),(report_path,'packet_study_sha256'),(protocol_path,'packet_study_protocol_sha256'),(Path(__file__),'script_sha256')):
        if sha256(path)!=protocol[key]: raise ValueError('Input changed during analysis')
    output={'status':'complete','sample_size':len(observations),'observations':observations,'correlations':correlations(observations),
            'protocol_sha256':sha256(OUT/'protocol.json')}
    write_json(OUT/'report.json',output)
    print('Compared CSV flag columns with first-packet flags for',len(observations),'matched examples.')


if __name__=='__main__': main()
