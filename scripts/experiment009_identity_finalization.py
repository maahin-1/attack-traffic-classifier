"""Compare two isolated extractor variants on synthetic PCAPs only."""
import csv
import difflib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from scapy.all import IP, UDP, rdpcap, wrpcap
from experiment009_second_extractor import ROOT, SOURCE, sha, udp, verify_source

OUT = ROOT / 'artifacts/experiment-009-identity-finalization'
OLD = ROOT / '.test-tmp/pycicflowmeter-correction-009'
NEW = ROOT / '.test-tmp/pycicflowmeter-identity-finalization-009'
PREVIOUS = ROOT / 'artifacts/experiment-009-correction-spike'
PLAN = ROOT / 'docs/EXPERIMENT-009-IDENTITY-FINALIZATION-PLAN.md'


def files_hash(root):
    return {p.name: sha(p) for p in sorted((root / 'pycicflowmeter').glob('*.py'))}


def replace_exact(path, before, after):
    data = path.read_text(encoding='utf-8')
    if data.count(before) != 1:
        raise ValueError(f'unexpected source in {path}')
    path.write_text(data.replace(before, after), encoding='utf-8', newline='')


def main():
    if sys.prefix == sys.base_prefix:
        raise RuntimeError('isolated environment required')
    verify_source()
    previous_protocol = json.loads((PREVIOUS / 'protocol.json').read_text(encoding='utf-8'))
    if files_hash(OLD) != previous_protocol['variant_hashes']:
        raise ValueError('previous variant differs from its recorded hashes')
    if OUT.exists() or NEW.exists():
        raise FileExistsError('output or variant already exists')
    OUT.mkdir(parents=True)
    shutil.copytree(OLD, NEW, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    init = NEW / 'pycicflowmeter/__init__.py'
    replace_exact(init, '        self._writer.write_row(flow_key, start_us or 0, vector)',
                  '        flow = self.analyzer.flows[flow_key]\n'
                  '        identity = f"{flow.forward_ip}:{flow.forward_port}->{flow.backward_ip}:{flow.backward_port} ({flow.protocol})"\n'
                  '        self._writer.write_row(identity, start_us or 0, vector)')
    analyzer = NEW / 'pycicflowmeter/analyzer.py'
    replace_exact(analyzer, '            current_time = self.current_time_us\n\n            # Add final duration',
                  '            current_time = flow.last_seen if flow.last_seen is not None else self.current_time_us\n\n            # Add final duration')
    patch = ''
    for name in ('__init__.py', 'analyzer.py', 'flow.py'):
        a = (SOURCE / 'pycicflowmeter' / name).read_text(encoding='utf-8').splitlines(True)
        b = (NEW / 'pycicflowmeter' / name).read_text(encoding='utf-8').splitlines(True)
        patch += ''.join(difflib.unified_diff(a, b, fromfile='upstream/' + name, tofile='experimental/' + name))
    (OUT / 'variant.patch').write_text(patch, encoding='utf-8')
    protocol = {'plan_sha256': sha(PLAN), 'runner_sha256': sha(Path(__file__)),
                'previous_protocol_sha256': sha(PREVIOUS / 'protocol.json'),
                'previous_variant_hashes': files_hash(OLD), 'new_variant_hashes': files_hash(NEW),
                'patch_sha256': sha(OUT / 'variant.patch'), 'python': sys.version,
                'dependencies': subprocess.run([sys.executable, '-m', 'pip', 'freeze'], capture_output=True, text=True, check=True).stdout.splitlines()}
    (OUT / 'protocol.json').write_text(json.dumps(protocol, indent=2) + '\n', encoding='utf-8')
    old_results = json.loads((PREVIOUS / 'report.json').read_text(encoding='utf-8'))
    fixtures = {}
    for name, result in old_results.items():
        if name == 'udp_single':
            path = ROOT / 'artifacts/experiment-009-second-extractor/udp_single.pcap'
        elif name in ('ethernet', 'linux_cooked_v1'):
            path = ROOT / 'artifacts/experiment-009-extractor-spike' / (name + '.pcap')
        else:
            path = PREVIOUS / (name + '.pcap')
        if sha(path) != result['fixture_sha256']:
            raise ValueError('prior fixture hash mismatch: ' + name)
        fixtures[name] = path
    new_cases = {
        'reverse_asymmetric': [udp(reverse=True, payload=b'aa'), udp(reverse=True, payload=b'bbbb', sec='1700000001.1'), udp(payload=b'ccc', sec='1700000002.1')],
        'interleaved_singletons': [udp(), udp(sport=12346, sec='1700000001.1')],
    }
    for name, packets in new_cases.items():
        fixtures[name] = OUT / (name + '.pcap')
        wrpcap(str(fixtures[name]), packets)
    observed = rdpcap(str(fixtures['reverse_asymmetric']))
    assert [(p[IP].src, p[UDP].sport, len(p[UDP].payload)) for p in observed] == [
        ('198.51.100.2', 53, 2), ('198.51.100.2', 53, 4), ('192.0.2.1', 12345, 3)]
    allowed = {'Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port',
               'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'}
    results = {}
    for name, path in fixtures.items():
        results[name] = {'fixture_sha256': sha(path)}
        for label, source in [('old', OLD), ('new', NEW)]:
            output = OUT / (name + '-' + label + '.csv')
            env = dict(os.environ, PYTHONPATH=str(source), PYTHONNOUSERSITE='1')
            args = [sys.executable, '-m', 'pycicflowmeter.cli', '-f', str(path), '-o', str(output), '--timeout', '120', '--activity-timeout', '5']
            done = subprocess.run(args, cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)
            with output.open(encoding='utf-8', newline='') as stream:
                rows = list(csv.DictReader(stream))
            results[name][label] = {'exit_code': done.returncode, 'stderr': done.stderr, 'rows': rows}
        a, b = results[name]['old']['rows'], results[name]['new']['rows']
        if len(a) != len(b):
            results[name]['differences'] = {'row_count': [len(a), len(b)]}
        else:
            results[name]['differences'] = {str(i): {k: [x[k], y[k]] for k in x if x[k] != y[k]}
                                               for i, (x, y) in enumerate(zip(a, b)) if x != y}
        results[name]['unexpected_fields'] = sorted({k for changes in results[name]['differences'].values() if isinstance(changes, dict) for k in changes if k not in allowed})
        if 'row_count' in results[name]['differences']:
            results[name]['unexpected_fields'].append('row_count')
    callback_code = 'import json,sys; from pycicflowmeter import FlowMeter; out=[]; m=FlowMeter(on_flow_finalized=lambda k,t,v:out.append([k,t])); m.process_pcap(sys.argv[1]); print(json.dumps(out))'
    callback = {}
    for label, source in [('old', OLD), ('new', NEW)]:
        env = dict(os.environ, PYTHONPATH=str(source), PYTHONNOUSERSITE='1')
        done = subprocess.run([sys.executable, '-c', callback_code, str(fixtures['reverse_asymmetric'])], cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)
        callback[label] = {'exit_code': done.returncode, 'stdout': done.stdout, 'stderr': done.stderr}
    verify_source()
    if (files_hash(OLD) != protocol['previous_variant_hashes'] or files_hash(NEW) != protocol['new_variant_hashes']
            or sha(PLAN) != protocol['plan_sha256'] or sha(Path(__file__)) != protocol['runner_sha256']):
        raise RuntimeError('protocol inputs changed')
    report = {'cases': results, 'callbacks': callback}
    (OUT / 'report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'cases': {n: {'old_rows': len(v['old']['rows']), 'new_rows': len(v['new']['rows']), 'differences': v['differences'], 'unexpected': v['unexpected_fields']} for n, v in results.items()}, 'callbacks_equal': callback['old']['stdout'] == callback['new']['stdout']}))


if __name__ == '__main__':
    main()
