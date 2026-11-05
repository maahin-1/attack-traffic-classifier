"""Distinguish population and sample packet-length standard deviations."""
import csv
import json
import os
import subprocess
import sys
from pathlib import Path

from scapy.all import wrpcap
from experiment009_second_extractor import ROOT, SOURCE, sha, udp, verify_source

OUT = ROOT / 'artifacts/experiment-009-std-fixture'
PLAN = ROOT / 'docs/EXPERIMENT-009-STD-FIXTURE-PLAN.md'


def main():
    if sys.prefix == sys.base_prefix:
        raise RuntimeError('isolated environment required')
    verify_source()
    if OUT.exists():
        raise FileExistsError(OUT)
    OUT.mkdir(parents=True)
    plan_hash, runner_hash = sha(PLAN), sha(Path(__file__))
    fixture = OUT / 'unequal_lengths.pcap'
    wrpcap(str(fixture), [udp(payload=b'abcd'), udp(payload=b'abcdefgh', sec='1700000001.1')])
    csv_path = OUT / 'flows.csv'
    env = dict(os.environ, PYTHONPATH=str(SOURCE), PYTHONNOUSERSITE='1')
    args = [sys.executable, '-m', 'pycicflowmeter.cli', '-f', str(fixture), '-o', str(csv_path),
            '--timeout', '120', '--activity-timeout', '5']
    done = subprocess.run(args, cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)
    with csv_path.open(encoding='utf-8', newline='') as stream:
        rows = list(csv.DictReader(stream))
    verify_source()
    if sha(PLAN) != plan_hash or sha(Path(__file__)) != runner_hash:
        raise RuntimeError('protocol changed')
    report = {'fixture_sha256': sha(fixture), 'plan_sha256': plan_hash,
              'runner_sha256': runner_hash, 'expected_payload_lengths': [4, 8],
              'population_std': 2.0, 'sample_std': 8 ** 0.5,
              'exit_code': done.returncode, 'stdout': done.stdout, 'stderr': done.stderr, 'rows': rows}
    (OUT / 'report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'exit_code': done.returncode, 'rows': len(rows),
                      'std': rows[0]['Fwd Packet Length Std'] if rows else None}))


if __name__ == '__main__':
    main()
