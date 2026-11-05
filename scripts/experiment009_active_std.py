"""Test isolated active/idle sample standard-deviation calculations."""
import csv
import difflib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from experiment009_second_extractor import ROOT, SOURCE, sha, verify_source
from experiment009_identity_finalization import files_hash
from experiment009_synack_fix import VARIANT as OLD

OUT = ROOT / 'artifacts/experiment-009-active-std'
NEW = ROOT / '.test-tmp/pycicflowmeter-active-std-009'
PLAN = ROOT / 'docs/EXPERIMENT-009-ACTIVE-STD-PLAN.md'
BOUNDARY = ROOT / 'artifacts/experiment-009-feature-boundaries'
REGRESSION = ROOT / 'artifacts/experiment-009-synack-fix'


def main():
    if sys.prefix == sys.base_prefix:
        raise RuntimeError('isolated environment required')
    verify_source()
    prev = json.loads((REGRESSION / 'protocol.json').read_text(encoding='utf-8'))
    if files_hash(OLD) != prev['new_source']:
        raise RuntimeError('previous variant hash mismatch')
    if OUT.exists() or NEW.exists():
        raise FileExistsError('output or variant exists')
    OUT.mkdir(parents=True)
    shutil.copytree(OLD, NEW, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    for filename, owner in [('flow.py', 'self'), ('analyzer.py', 'flow')]:
        path = NEW / 'pycicflowmeter' / filename
        content = path.read_text(encoding='utf-8')
        for field in ('active_times', 'idle_times'):
            old = f'statistics.pstdev({owner}.{field})'
            replacement = f'(statistics.stdev({owner}.{field}) if len({owner}.{field}) > 1 else 0.0)'
            if content.count(old) != 1:
                raise RuntimeError('unexpected source: ' + old)
            content = content.replace(old, replacement)
        path.write_text(content, encoding='utf-8', newline='')
    patch = ''
    for name in ('__init__.py', 'analyzer.py', 'flow.py'):
        a = (SOURCE / 'pycicflowmeter' / name).read_text(encoding='utf-8').splitlines(True)
        b = (NEW / 'pycicflowmeter' / name).read_text(encoding='utf-8').splitlines(True)
        patch += ''.join(difflib.unified_diff(a, b, fromfile='upstream/' + name, tofile='experimental/' + name))
    (OUT / 'variant.patch').write_text(patch, encoding='utf-8')
    protocol = {'plan_sha256': sha(PLAN), 'runner_sha256': sha(Path(__file__)),
                'old_source': files_hash(OLD), 'new_source': files_hash(NEW), 'patch_sha256': sha(OUT / 'variant.patch'),
                'old_protocol_sha256': sha(REGRESSION / 'protocol.json'), 'boundary_protocol_sha256': sha(BOUNDARY / 'protocol.json'),
                'old_report_sha256': sha(REGRESSION / 'report.json'), 'boundary_report_sha256': sha(BOUNDARY / 'report.json'),
                'python': sys.version, 'dependencies': subprocess.run([sys.executable, '-m', 'pip', 'freeze'], capture_output=True, text=True, check=True).stdout.splitlines()}
    (OUT / 'protocol.json').write_text(json.dumps(protocol, indent=2) + '\n', encoding='utf-8')
    boundary = json.loads((BOUNDARY / 'report.json').read_text(encoding='utf-8'))
    regression = json.loads((REGRESSION / 'report.json').read_text(encoding='utf-8'))['cases']
    cases = {}
    for name, value in boundary.items():
        cases['boundary_' + name] = (BOUNDARY / (name + '.pcap'), value['fixture_sha256'], value['rows'])
    for name, value in regression.items():
        if name in ('reverse_asymmetric', 'interleaved_singletons'):
            path = ROOT / 'artifacts/experiment-009-identity-finalization' / (name + '.pcap')
        elif name == 'udp_single':
            path = ROOT / 'artifacts/experiment-009-second-extractor/udp_single.pcap'
        elif name in ('ethernet', 'linux_cooked_v1'):
            path = ROOT / 'artifacts/experiment-009-extractor-spike' / (name + '.pcap')
        elif name == 'synack_first':
            path = ROOT / 'artifacts/experiment-009-synack-v2/synack_first.pcap'
        else:
            path = ROOT / 'artifacts/experiment-009-correction-spike' / (name + '.pcap')
        cases['regression_' + name] = (path, value['fixture_sha256'], value['rows'])
    results = {}
    env = dict(os.environ, PYTHONPATH=str(NEW), PYTHONNOUSERSITE='1')
    for name, (path, digest, reference) in cases.items():
        if sha(path) != digest:
            raise RuntimeError('fixture hash mismatch: ' + name)
        output = OUT / (name + '.csv')
        done = subprocess.run([sys.executable, '-m', 'pycicflowmeter.cli', '-f', str(path), '-o', str(output), '--timeout', '120', '--activity-timeout', '5'], cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)
        with output.open(encoding='utf-8', newline='') as stream:
            rows = list(csv.DictReader(stream))
        differences = {'row_count': [len(reference), len(rows)]} if len(reference) != len(rows) else {
            str(i): {k: [a[k], b[k]] for k in a if a[k] != b[k]} for i, (a, b) in enumerate(zip(reference, rows)) if a != b}
        results[name] = {'fixture_sha256': digest, 'exit_code': done.returncode, 'stderr': done.stderr, 'rows': rows, 'differences': differences}
    verify_source()
    if (sha(PLAN) != protocol['plan_sha256'] or sha(Path(__file__)) != protocol['runner_sha256'] or files_hash(OLD) != protocol['old_source'] or files_hash(NEW) != protocol['new_source']
            or sha(REGRESSION / 'report.json') != protocol['old_report_sha256'] or sha(BOUNDARY / 'report.json') != protocol['boundary_report_sha256']):
        raise RuntimeError('protocol changed')
    (OUT / 'report.json').write_text(json.dumps(results, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({name: {'exit_code': result['exit_code'], 'differences': result['differences']} for name, result in results.items() if result['exit_code'] or result['differences']}))


if __name__ == '__main__':
    main()
