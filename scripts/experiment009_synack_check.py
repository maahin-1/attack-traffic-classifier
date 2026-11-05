"""Synthetic check of TCP direction when capture begins with SYN-ACK."""
import csv
import json
import os
import subprocess
import sys
from pathlib import Path
from scapy.all import IP, TCP, rdpcap, wrpcap
from experiment009_second_extractor import ROOT, sha, verify_source
from experiment009_correction_spike import tcp
from experiment009_identity_finalization import OLD, NEW, files_hash

OUT = ROOT / 'artifacts/experiment-009-synack-v2'
PLAN = ROOT / 'docs/EXPERIMENT-009-SYNACK-PLAN.md'
PREVIOUS = ROOT / 'artifacts/experiment-009-identity-finalization/protocol.json'


def main():
    if sys.prefix == sys.base_prefix:
        raise RuntimeError('isolated environment required')
    verify_source()
    prior = json.loads(PREVIOUS.read_text(encoding='utf-8'))
    if files_hash(OLD) != prior['previous_variant_hashes'] or files_hash(NEW) != prior['new_variant_hashes']:
        raise RuntimeError('variant source hash mismatch')
    if OUT.exists():
        raise FileExistsError(OUT)
    OUT.mkdir(parents=True)
    fixture = OUT / 'synack_first.pcap'
    wrpcap(str(fixture), [tcp(reverse=True, flags='SA'), tcp(flags='A', sec='1700000001.1')])
    packets = rdpcap(str(fixture))
    assert [(p[IP].src, p[TCP].sport, int(p[TCP].flags)) for p in packets] == [('198.51.100.2', 443, 0x12), ('192.0.2.1', 12345, 0x10)]
    protocol = {'fixture_sha256': sha(fixture), 'plan_sha256': sha(PLAN), 'runner_sha256': sha(Path(__file__)),
                'previous_protocol_sha256': sha(PREVIOUS), 'old_source': files_hash(OLD), 'new_source': files_hash(NEW)}
    results = {}
    for label, source in [('old', OLD), ('new', NEW)]:
        output = OUT / (label + '.csv')
        env = dict(os.environ, PYTHONPATH=str(source), PYTHONNOUSERSITE='1')
        done = subprocess.run([sys.executable, '-m', 'pycicflowmeter.cli', '-f', str(fixture), '-o', str(output), '--timeout', '120', '--activity-timeout', '5'], cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)
        with output.open(encoding='utf-8', newline='') as stream:
            rows = list(csv.DictReader(stream))
        results[label] = {'exit_code': done.returncode, 'stderr': done.stderr, 'rows': rows}
    verify_source()
    if sha(fixture) != protocol['fixture_sha256'] or sha(PLAN) != protocol['plan_sha256'] or sha(Path(__file__)) != protocol['runner_sha256'] or files_hash(OLD) != protocol['old_source'] or files_hash(NEW) != protocol['new_source']:
        raise RuntimeError('protocol changed')
    (OUT / 'report.json').write_text(json.dumps({'protocol': protocol, 'results': results}, indent=2) + '\n', encoding='utf-8')
    keys = ('Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Total Fwd Packets', 'Total Backward Packets')
    print(json.dumps({label: {'exit_code': x['exit_code'], 'rows': [{k: row[k] for k in keys} for row in x['rows']]} for label, x in results.items()}))


if __name__ == '__main__':
    main()
