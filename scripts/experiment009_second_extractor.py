"""Synthetic-only CLI spike for a pinned third-party extractor."""
import csv
import hashlib
import json
import os
import subprocess
import sys
import zipfile
from decimal import Decimal
from pathlib import Path

from scapy.all import Ether, IP, UDP, Raw, wrpcap

ROOT = Path(__file__).resolve().parents[1]
COMMIT = '4432a32e05491c110f78fe80a59ab733b145d2cb'
PREFIX = 'pycicflowmeter-' + COMMIT
ARCHIVE = ROOT / '.test-tmp/pycicflowmeter-4432a32.zip'
SOURCE = ROOT / '.test-tmp/pycicflowmeter-source-009' / PREFIX
OUT = ROOT / 'artifacts/experiment-009-second-extractor'
PLAN = ROOT / 'docs/EXPERIMENT-009-SECOND-EXTRACTOR-PLAN.md'
EXPECTED_SHA = 'db4a1b578fb159503db963bcba48300d0ad42fc9237d8cf1c62dbf05e3455850'
FEATURES = ['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
            'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
            *['Fwd Packet Length ' + x for x in ('Max', 'Min', 'Mean', 'Std')],
            *['Bwd Packet Length ' + x for x in ('Max', 'Min', 'Mean', 'Std')],
            *['Flow IAT ' + x for x in ('Mean', 'Std', 'Max', 'Min')],
            'Fwd IAT Total', 'Bwd IAT Total',
            *['Active ' + x for x in ('Mean', 'Std', 'Max', 'Min')],
            *['Idle ' + x for x in ('Mean', 'Std', 'Max', 'Min')]]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def udp(reverse=False, sport=12345, dport=53, payload=b'abcd', sec='1700000000.1'):
    a, b = '192.0.2.1', '198.51.100.2'
    if reverse:
        a, b, sport, dport = b, a, dport, sport
    pkt = Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') / IP(src=a, dst=b) / UDP(sport=sport, dport=dport) / Raw(payload)
    pkt.time = Decimal(sec)
    return pkt


def verify_source():
    if sha(ARCHIVE) != EXPECTED_SHA:
        raise ValueError('source archive hash mismatch')
    with zipfile.ZipFile(ARCHIVE) as archive:
        for name in archive.namelist():
            if name.startswith(PREFIX + '/pycicflowmeter/') and name.endswith('.py'):
                path = SOURCE / Path(name).relative_to(PREFIX)
                if path.read_bytes() != archive.read(name):
                    raise ValueError('source mismatch: ' + name)


def main():
    if sys.prefix == sys.base_prefix:
        raise RuntimeError('isolated Python environment required')
    verify_source()
    if OUT.exists():
        raise FileExistsError(OUT)
    OUT.mkdir(parents=True)
    protocol = {'commit': COMMIT, 'archive_sha256': EXPECTED_SHA, 'runner_sha256': sha(Path(__file__)),
                'plan_sha256': sha(PLAN), 'python': sys.version,
                'dependencies': subprocess.run([sys.executable, '-m', 'pip', 'freeze'],
                                               text=True, capture_output=True, check=True).stdout.splitlines(),
                'features': FEATURES}
    (OUT / 'protocol.json').write_text(json.dumps(protocol, indent=2) + '\n', encoding='utf-8')
    previous = ROOT / 'artifacts/experiment-009-extractor-spike'
    previous_report = json.loads((previous / 'report.json').read_text(encoding='utf-8'))
    fixtures = {}
    for name in ('ethernet', 'linux_cooked_v1'):
        p = previous / (name + '.pcap')
        if sha(p) != previous_report['cases'][name]['fixture_sha256']:
            raise ValueError('fixture hash changed')
        fixtures[name] = p
    for name, packets in {
        'udp_single': [udp()],
        'udp_reverse': [udp(), udp(reverse=True, sec='1700000002.1')],
        'udp_two_flows': [udp(), udp(sport=12346, sec='1700000000.2')],
    }.items():
        fixtures[name] = OUT / (name + '.pcap')
        wrpcap(str(fixtures[name]), packets)
    results = {}
    env = dict(os.environ, PYTHONPATH=str(SOURCE), PYTHONNOUSERSITE='1')
    for name, path in fixtures.items():
        output = OUT / (name + '.csv')
        args = [sys.executable, '-m', 'pycicflowmeter.cli', '-f', str(path), '-o', str(output),
                '--timeout', '120', '--activity-timeout', '5']
        p = subprocess.run(args, cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)
        result = {'fixture_sha256': sha(path), 'exit_code': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr}
        if output.exists():
            with output.open(encoding='utf-8-sig', newline='') as stream:
                reader = csv.DictReader(stream)
                result['columns'], result['rows'] = reader.fieldnames, list(reader)
            result['missing_features'] = [x for x in FEATURES if x not in (result['columns'] or [])]
            result['placeholder_features'] = {x: sum(row.get(x) in ('-1', '-1.0', '', None) for row in result['rows'])
                                              for x in FEATURES if any(row.get(x) in ('-1', '-1.0', '', None) for row in result['rows'])}
        results[name] = result
    verify_source()
    if sha(Path(__file__)) != protocol['runner_sha256'] or sha(PLAN) != protocol['plan_sha256']:
        raise RuntimeError('protocol inputs changed')
    (OUT / 'report.json').write_text(json.dumps(results, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: {'exit_code': v['exit_code'], 'rows': len(v.get('rows', [])),
                           'missing_features': v.get('missing_features'), 'placeholders': v.get('placeholder_features')}
                      for k, v in results.items()}))


if __name__ == '__main__':
    main()
