"""Characterize the isolated extractor on synthetic flow and capture edges."""
import csv
import json
import math
import os
import subprocess
import sys
from decimal import Decimal
from pathlib import Path

from scapy.all import Ether, IP, TCP, UDP, fragment, rdpcap, wrpcap
from experiment009_second_extractor import ROOT, sha, udp, verify_source
from experiment009_correction_spike import tcp
from experiment009_identity_finalization import files_hash
from experiment009_synack_fix import VARIANT

OUT = ROOT / 'artifacts/experiment-009-feature-boundaries'
PLAN = ROOT / 'docs/EXPERIMENT-009-FEATURE-BOUNDARY-PLAN.md'
PREVIOUS = ROOT / 'artifacts/experiment-009-synack-fix/protocol.json'


def stamp(seconds):
    return str(Decimal('1700000000.1') + Decimal(str(seconds)))


def main():
    if sys.prefix == sys.base_prefix:
        raise RuntimeError('isolated environment required')
    verify_source()
    prior = json.loads(PREVIOUS.read_text(encoding='utf-8'))
    if files_hash(VARIANT) != prior['new_source']:
        raise RuntimeError('experimental source mismatch')
    if OUT.exists():
        raise FileExistsError(OUT)
    OUT.mkdir(parents=True)
    original = udp(payload=b'x' * 40)
    fragments = []
    for i, piece in enumerate(fragment(original[IP], fragsize=16)):
        packet = Ether(src=original.src, dst=original.dst) / piece
        packet.time = Decimal(stamp(Decimal(i) / 1000))
        fragments.append(packet)
    fixtures = {
        'activity_variance': [udp(sec=stamp(x)) for x in (0, 1, 7, 9, 17, 20)],
        'activity_exact': [udp(sec=stamp(x)) for x in (0, 1, 6, 7)],
        'equal_time': [udp(sec=stamp(0)), udp(reverse=True, sec=stamp(0))],
        'out_of_order': [udp(sec=stamp(0)), udp(sec=stamp(2)), udp(reverse=True, sec=stamp(1))],
        'tcp_rst': [tcp(), tcp(reverse=True, flags='RA', sec=stamp(1)), tcp(sec=stamp(2))],
        'udp_unfragmented': [original],
        'udp_fragmented': fragments,
    }
    protocol = {'plan_sha256': sha(PLAN), 'runner_sha256': sha(Path(__file__)),
                'source_protocol_sha256': sha(PREVIOUS), 'source_hashes': files_hash(VARIANT),
                'python': sys.version, 'dependencies': subprocess.run([sys.executable, '-m', 'pip', 'freeze'], capture_output=True, text=True, check=True).stdout.splitlines(),
                'active_idle_reference_us': {'active_mean': 2e6, 'active_min': 1e6, 'active_max': 3e6, 'active_sample_std': 1e6,
                                             'idle_mean': 7e6, 'idle_min': 6e6, 'idle_max': 8e6, 'idle_sample_std': math.sqrt(2)*1e6}}
    (OUT / 'protocol.json').write_text(json.dumps(protocol, indent=2) + '\n', encoding='utf-8')
    results = {}
    for name, packets in fixtures.items():
        path = OUT / (name + '.pcap')
        wrpcap(str(path), packets)
        decoded = rdpcap(str(path))
        inputs = [{'time': str(pkt.time), 'src': pkt[IP].src, 'dst': pkt[IP].dst,
                   'ip_proto': pkt[IP].proto, 'fragment_offset': pkt[IP].frag,
                   'more_fragments': bool(int(pkt[IP].flags) & 1),
                   'has_udp': UDP in pkt, 'has_tcp': TCP in pkt,
                   'transport_payload_bytes': len(pkt[UDP].payload) if UDP in pkt else len(pkt[TCP].payload) if TCP in pkt else None}
                  for pkt in decoded]
        out = OUT / (name + '.csv')
        env = dict(os.environ, PYTHONPATH=str(VARIANT), PYTHONNOUSERSITE='1')
        cmd = [sys.executable, '-m', 'pycicflowmeter.cli', '-f', str(path), '-o', str(out), '--timeout', '120', '--activity-timeout', '5']
        done = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)
        with out.open(encoding='utf-8', newline='') as stream:
            rows = list(csv.DictReader(stream))
        results[name] = {'fixture_sha256': sha(path), 'inputs': inputs, 'exit_code': done.returncode,
                         'stdout': done.stdout, 'stderr': done.stderr, 'rows': rows}
    verify_source()
    if sha(PLAN) != protocol['plan_sha256'] or sha(Path(__file__)) != protocol['runner_sha256'] or files_hash(VARIANT) != protocol['source_hashes']:
        raise RuntimeError('protocol changed during experiment')
    (OUT / 'report.json').write_text(json.dumps(results, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({n: {'input_packets': len(v['inputs']), 'rows': len(v['rows']), 'exit_code': v['exit_code'],
                          'error_logged': 'ERROR' in v['stderr']} for n, v in results.items()}))


if __name__ == '__main__':
    main()
