"""Compare a narrowly patched, isolated extractor with its pinned upstream."""
import csv
import difflib
import json
import math
import os
import shutil
import subprocess
import sys
from decimal import Decimal
from pathlib import Path

from scapy.all import Ether, IP, TCP, wrpcap
from experiment009_second_extractor import ROOT, SOURCE, FEATURES, sha, udp, verify_source

OUT = ROOT / 'artifacts/experiment-009-correction-spike'
VARIANT = ROOT / '.test-tmp/pycicflowmeter-correction-009'
PLAN = ROOT / 'docs/EXPERIMENT-009-CORRECTION-SPIKE-PLAN.md'


def tcp(reverse=False, flags='A', sec='1700000000.1'):
    a, b, sport, dport = '192.0.2.1', '198.51.100.2', 12345, 443
    if reverse:
        a, b, sport, dport = b, a, dport, sport
    pkt = Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') / IP(src=a, dst=b) / TCP(sport=sport, dport=dport, flags=flags)
    pkt.time = Decimal(sec)
    return pkt


def main():
    if sys.prefix == sys.base_prefix:
        raise RuntimeError('isolated environment required')
    verify_source()
    if OUT.exists() or VARIANT.exists():
        raise FileExistsError('spike output or variant already exists')
    OUT.mkdir(parents=True)
    VARIANT.mkdir(parents=True)
    shutil.copytree(SOURCE / 'pycicflowmeter', VARIANT / 'pycicflowmeter',
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    shutil.copy2(SOURCE / 'LICENSE', VARIANT / 'LICENSE')
    flow = VARIANT / 'pycicflowmeter/flow.py'
    before = flow.read_text(encoding='utf-8')
    after = before
    for direction in ('fwd', 'bwd'):
        original = f'statistics.pstdev(self.{direction}_payload_sizes)'
        replacement = f'(statistics.stdev(self.{direction}_payload_sizes) if len(self.{direction}_payload_sizes) > 1 else 0.0)'
        if after.count(original) != 1:
            raise ValueError('unexpected upstream source')
        after = after.replace(original, replacement)
    flow.write_text(after, encoding='utf-8', newline='')
    diff = ''.join(difflib.unified_diff(before.splitlines(True), after.splitlines(True), fromfile='upstream/flow.py', tofile='experimental/flow.py'))
    (OUT / 'variant.patch').write_text(diff, encoding='utf-8')
    variant_hashes = {p.name: sha(p) for p in sorted((VARIANT / 'pycicflowmeter').glob('*.py'))}
    protocol = {'plan_sha256': sha(PLAN), 'runner_sha256': sha(Path(__file__)),
                'variant_hashes': variant_hashes, 'upstream_flow_sha256': sha(SOURCE / 'pycicflowmeter/flow.py'),
                'patch_sha256': sha(OUT / 'variant.patch'), 'python': sys.version,
                'dependencies': subprocess.run([sys.executable, '-m', 'pip', 'freeze'], capture_output=True, text=True, check=True).stdout.splitlines()}
    (OUT / 'protocol.json').write_text(json.dumps(protocol, indent=2) + '\n', encoding='utf-8')
    fixture_packets = {
        'length_and_gap': [udp(payload=b'abcd'), udp(reverse=True, payload=b'xyz', sec='1700000001.1'),
                           udp(payload=b'abcdefgh', sec='1700000003.1'), udp(reverse=True, payload=b'abcdefghi', sec='1700000004.1')],
        'reverse_first': [udp(reverse=True), udp(sec='1700000001.1')],
        'activity': [udp(sec='1700000000.1'), udp(sec='1700000001.1'), udp(sec='1700000006.099999'),
                     udp(sec='1700000011.099999'), udp(sec='1700000016.1'), udp(sec='1700000017.1')],
        'timeout_below': [udp(), udp(sec='1700000120.099999')],
        'timeout_equal': [udp(), udp(sec='1700000120.1')],
        'timeout_above': [udp(), udp(sec='1700000120.100001')],
        'tcp_fin': [tcp(), tcp(flags='FA', sec='1700000001.1'), tcp(reverse=True, flags='FA', sec='1700000002.1'), tcp(flags='A', sec='1700000003.1')],
    }
    fixtures = {}
    for name, packets in fixture_packets.items():
        fixtures[name] = OUT / (name + '.pcap')
        wrpcap(str(fixtures[name]), packets)
    previous = ROOT / 'artifacts/experiment-009-second-extractor'
    prior_report = json.loads((previous / 'report.json').read_text(encoding='utf-8'))
    for name in ('udp_single', 'ethernet', 'linux_cooked_v1'):
        p = (previous / 'udp_single.pcap') if name == 'udp_single' else (ROOT / 'artifacts/experiment-009-extractor-spike' / (name + '.pcap'))
        if sha(p) != prior_report[name]['fixture_sha256']:
            raise ValueError('previous fixture hash mismatch')
        fixtures[name] = p
    results = {}
    for name, fixture in fixtures.items():
        results[name] = {'fixture_sha256': sha(fixture)}
        for label, source in [('upstream', SOURCE), ('variant', VARIANT)]:
            output = OUT / (name + '-' + label + '.csv')
            env = dict(os.environ, PYTHONPATH=str(source), PYTHONNOUSERSITE='1')
            args = [sys.executable, '-m', 'pycicflowmeter.cli', '-f', str(fixture), '-o', str(output), '--timeout', '120', '--activity-timeout', '5']
            done = subprocess.run(args, cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)
            with output.open(encoding='utf-8', newline='') as stream:
                rows = list(csv.DictReader(stream))
            results[name][label] = {'exit_code': done.returncode, 'stderr': done.stderr, 'rows': rows}
        a, b = results[name]['upstream']['rows'], results[name]['variant']['rows']
        if len(a) != len(b):
            results[name]['differences'] = {'row_count': [len(a), len(b)]}
        else:
            results[name]['differences'] = {str(i): {k: [x[k], y[k]] for k in x if x[k] != y[k]}
                                               for i, (x, y) in enumerate(zip(a, b)) if x != y}
    verify_source()
    if sha(PLAN) != protocol['plan_sha256'] or sha(Path(__file__)) != protocol['runner_sha256'] or {p.name: sha(p) for p in sorted((VARIANT / 'pycicflowmeter').glob('*.py'))} != variant_hashes:
        raise RuntimeError('protocol inputs changed during experiment')
    (OUT / 'report.json').write_text(json.dumps(results, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({n: {'upstream_rows': len(v['upstream']['rows']), 'variant_rows': len(v['variant']['rows']), 'differences': v['differences']} for n, v in results.items()}))


if __name__ == '__main__':
    main()
