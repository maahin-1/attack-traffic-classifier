"""Exercise the candidate flow session on previously generated synthetic fixtures."""
import csv
import hashlib
import json
import subprocess
import sys
import traceback
from pathlib import Path

from scapy.layers.inet import IP, TCP, UDP
from scapy.utils import PcapReader
from cicflowmeter.flow_session import FlowSession

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'artifacts/experiment-009-extractor-spike'
OUT = ROOT / 'artifacts/experiment-009-extractor-api-spike'
PLAN = ROOT / 'docs/EXPERIMENT-009-EXTRACTOR-SPIKE-PLAN.md'
WHEEL = ROOT / '.test-tmp/extractor-wheels-009/cicflowmeter-0.4.0-py3-none-any.whl'
EXPECTED = '5bcef1ef131a53a037a47b007b33b5e73d4218033fdf6cb9f3208533180c30be'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    if sys.prefix == sys.base_prefix or sha(WHEEL) != EXPECTED:
        raise RuntimeError('isolated environment and pinned wheel required')
    original = json.loads((SOURCE / 'report.json').read_text(encoding='utf-8'))
    if OUT.exists():
        raise FileExistsError(OUT)
    OUT.mkdir(parents=True)
    protocol = {'runner_sha256': sha(Path(__file__)), 'plan_sha256': sha(PLAN),
                'wheel_sha256': sha(WHEEL), 'python': sys.version,
                'dependencies': subprocess.run([sys.executable, '-m', 'pip', 'freeze'],
                                               capture_output=True, text=True, check=True).stdout.splitlines()}
    (OUT / 'protocol.json').write_text(json.dumps(protocol, indent=2) + '\n', encoding='utf-8')
    results = {}
    for kind in ('ethernet', 'linux_cooked_v1'):
        path = SOURCE / (kind + '.pcap')
        if sha(path) != original['cases'][kind]['fixture_sha256']:
            raise RuntimeError('fixture hash mismatch')
        output = OUT / (kind + '.csv')
        result = {'fixture_sha256': sha(path), 'packets_read': 0, 'packets_submitted': 0}
        try:
            session = FlowSession(output_mode='csv', output=str(output))
            with PcapReader(str(path)) as packets:
                for pkt in packets:
                    result['packets_read'] += 1
                    if IP in pkt and (TCP in pkt or UDP in pkt):
                        result['packets_submitted'] += 1
                        session.process(pkt)
            session.flush_flows()
            result['status'] = 'completed'
        except Exception:
            result['status'] = 'failed'
            result['error'] = traceback.format_exc()
        if output.is_file():
            with output.open(encoding='utf-8-sig', newline='') as stream:
                reader = csv.DictReader(stream)
                result.update(columns=reader.fieldnames, rows=list(reader))
        results[kind] = result
    if sha(WHEEL) != EXPECTED or sha(Path(__file__)) != protocol['runner_sha256'] or sha(PLAN) != protocol['plan_sha256']:
        raise RuntimeError('protocol inputs changed during execution')
    (OUT / 'report.json').write_text(json.dumps(results, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: {'status': v['status'], 'packets': v['packets_submitted'],
                          'rows': len(v.get('rows', [])), 'error': v.get('error')} for k, v in results.items()}))


if __name__ == '__main__':
    main()
