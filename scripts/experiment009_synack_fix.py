"""Test a narrow first-observed TCP direction correction on synthetic PCAPs."""
import csv
import difflib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from experiment009_second_extractor import ROOT, SOURCE, sha, verify_source
from experiment009_identity_finalization import NEW, files_hash

OUT = ROOT / 'artifacts/experiment-009-synack-fix'
VARIANT = ROOT / '.test-tmp/pycicflowmeter-synack-fix-009'
PREVIOUS = ROOT / 'artifacts/experiment-009-identity-finalization'
SYNACK = ROOT / 'artifacts/experiment-009-synack-v2'
PLAN = ROOT / 'docs/EXPERIMENT-009-SYNACK-FIX-PLAN.md'


def main():
    if sys.prefix == sys.base_prefix:
        raise RuntimeError('isolated environment required')
    verify_source()
    previous_protocol = json.loads((PREVIOUS / 'protocol.json').read_text(encoding='utf-8'))
    previous_report = json.loads((PREVIOUS / 'report.json').read_text(encoding='utf-8'))
    syn = json.loads((SYNACK / 'report.json').read_text(encoding='utf-8'))
    if files_hash(NEW) != previous_protocol['new_variant_hashes']:
        raise RuntimeError('previous source mismatch')
    if OUT.exists() or VARIANT.exists():
        raise FileExistsError('output or source copy already exists')
    OUT.mkdir(parents=True)
    shutil.copytree(NEW, VARIANT, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    analyzer = VARIANT / 'pycicflowmeter/analyzer.py'
    source = analyzer.read_text(encoding='utf-8')
    # The exact expressions occur only in the two SYN-ACK initialization branches.
    replacements = {
        'forward_ip = packet[IP].dst if IP in packet else packet[IPv6].dst': 'forward_ip = packet[IP].src if IP in packet else packet[IPv6].src',
        'backward_ip = packet[IP].src if IP in packet else packet[IPv6].src': 'backward_ip = packet[IP].dst if IP in packet else packet[IPv6].dst',
        'forward_port = tcp.dport': 'forward_port = tcp.sport',
        'backward_port = tcp.sport': 'backward_port = tcp.dport',
    }
    for old, new in replacements.items():
        if source.count(old) != 2:
            raise ValueError('unexpected number of SYN-ACK expressions: ' + old)
        source = source.replace(old, new)
    analyzer.write_text(source, encoding='utf-8', newline='')
    patch = ''
    for name in ('__init__.py', 'analyzer.py', 'flow.py'):
        a = (SOURCE / 'pycicflowmeter' / name).read_text(encoding='utf-8').splitlines(True)
        b = (VARIANT / 'pycicflowmeter' / name).read_text(encoding='utf-8').splitlines(True)
        patch += ''.join(difflib.unified_diff(a, b, fromfile='upstream/' + name, tofile='experimental/' + name))
    (OUT / 'variant.patch').write_text(patch, encoding='utf-8')
    protocol = {'plan_sha256': sha(PLAN), 'runner_sha256': sha(Path(__file__)),
                'previous_protocol_sha256': sha(PREVIOUS / 'protocol.json'),
                'previous_source': files_hash(NEW), 'new_source': files_hash(VARIANT),
                'patch_sha256': sha(OUT / 'variant.patch'), 'python': sys.version,
                'dependencies': subprocess.run([sys.executable, '-m', 'pip', 'freeze'], capture_output=True, text=True, check=True).stdout.splitlines()}
    (OUT / 'protocol.json').write_text(json.dumps(protocol, indent=2) + '\n', encoding='utf-8')
    fixtures = {}
    for name, result in previous_report['cases'].items():
        if name in ('reverse_asymmetric', 'interleaved_singletons'):
            p = PREVIOUS / (name + '.pcap')
        elif name == 'udp_single':
            p = ROOT / 'artifacts/experiment-009-second-extractor/udp_single.pcap'
        elif name in ('ethernet', 'linux_cooked_v1'):
            p = ROOT / 'artifacts/experiment-009-extractor-spike' / (name + '.pcap')
        else:
            p = ROOT / 'artifacts/experiment-009-correction-spike' / (name + '.pcap')
        if sha(p) != result['fixture_sha256']:
            raise RuntimeError('fixture changed: ' + name)
        fixtures[name] = p
    fixtures['synack_first'] = SYNACK / 'synack_first.pcap'
    if sha(fixtures['synack_first']) != syn['protocol']['fixture_sha256']:
        raise RuntimeError('SYN-ACK fixture changed')
    results = {}
    for name, path in fixtures.items():
        output = OUT / (name + '.csv')
        env = dict(os.environ, PYTHONPATH=str(VARIANT), PYTHONNOUSERSITE='1')
        done = subprocess.run([sys.executable, '-m', 'pycicflowmeter.cli', '-f', str(path), '-o', str(output), '--timeout', '120', '--activity-timeout', '5'], cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)
        with output.open(encoding='utf-8', newline='') as stream:
            rows = list(csv.DictReader(stream))
        reference = syn['results']['new']['rows'] if name == 'synack_first' else previous_report['cases'][name]['new']['rows']
        differences = {'row_count': [len(reference), len(rows)]} if len(reference) != len(rows) else {
            str(i): {k: [a[k], b[k]] for k in a if a[k] != b[k]} for i, (a, b) in enumerate(zip(reference, rows)) if a != b}
        results[name] = {'fixture_sha256': sha(path), 'exit_code': done.returncode, 'stderr': done.stderr, 'rows': rows, 'differences': differences}
    callback_code = 'import json,sys; from pycicflowmeter import FlowMeter; out=[]; m=FlowMeter(on_flow_finalized=lambda k,t,v:out.append([k,t])); m.process_pcap(sys.argv[1]); print(json.dumps(out))'
    env = dict(os.environ, PYTHONPATH=str(VARIANT), PYTHONNOUSERSITE='1')
    cb = subprocess.run([sys.executable, '-c', callback_code, str(fixtures['reverse_asymmetric'])], cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)
    verify_source()
    if sha(PLAN) != protocol['plan_sha256'] or sha(Path(__file__)) != protocol['runner_sha256'] or files_hash(VARIANT) != protocol['new_source'] or files_hash(NEW) != protocol['previous_source']:
        raise RuntimeError('protocol changed')
    report = {'cases': results, 'callback': {'exit_code': cb.returncode, 'stdout': cb.stdout, 'stderr': cb.stderr}}
    (OUT / 'report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'cases': {k: {'exit_code': v['exit_code'], 'differences': v['differences']} for k, v in results.items()}, 'callback_exit': cb.returncode}))


if __name__ == '__main__':
    main()
