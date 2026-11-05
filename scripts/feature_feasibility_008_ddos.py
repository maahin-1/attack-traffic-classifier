"""Label-independent development sample of CIC-DDoS2019 calibration data."""
import csv
import io
import json
import math
import sqlite3
import sys
import time
import zipfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from attack_traffic.experiment007_input import ALIASES, ARCHIVES, FAMILIES, sha256
from attack_traffic.prepare import FEATURES, selected_record
from attack_traffic.support_extract import feature_digest
from scripts.assess_experiment007 import write_json
from scripts.feature_feasibility_008 import FLAGS

OUT = ROOT / 'artifacts/experiment-008-ddos-development'
AUDIT = ROOT / 'artifacts/experiment-007-quality-audit/report.json'
SOURCE = ROOT / 'data/cicddos2019' / ARCHIVES['calibration'][0]
MODES = ('base', 'protocol', 'flags', 'protocol_and_flags')


def group_summary(db, mode):
    row = db.execute('''SELECT COUNT(*), SUM(CASE WHEN benign>0 AND attack>0 THEN 1 ELSE 0 END),
        SUM(CASE WHEN benign>0 AND attack>0 THEN benign+attack ELSE 0 END),
        SUM(CASE WHEN benign>0 AND attack>0 THEN min(benign,attack) ELSE 0 END)
        FROM groups WHERE mode=?''', (mode,)).fetchone()
    return dict(zip(('groups', 'conflicting_groups', 'rows_in_conflicting_groups', 'minority_label_rows_lower_bound'), (x or 0 for x in row)))


def main():
    audit = json.loads(AUDIT.read_text(encoding='utf-8'))
    if audit['status'] != 'complete' or sha256(SOURCE) != ARCHIVES['calibration'][1]:
        raise ValueError('Calibration source or audit mismatch')
    OUT.mkdir(parents=True, exist_ok=False)
    dependency_paths = [Path(__file__), ROOT / 'attack_traffic/experiment007_input.py', ROOT / 'attack_traffic/prepare.py', ROOT / 'attack_traffic/support_extract.py', ROOT / 'scripts/feature_feasibility_008.py']
    hashes = {p.relative_to(ROOT).as_posix(): sha256(p) for p in dependency_paths}
    protocol = {'source_sha256': ARCHIVES['calibration'][1], 'audit_sha256': sha256(AUDIT), 'dependencies': hashes,
                'source_date': '2018-12-01', 'denominator': 100,
                'selection': 'BLAKE2b-64(subset-v1:archive_sha256:member:csv_record_number) modulo 100 == 0, before reading labels',
                'features': {'protocol': ['Protocol'], 'flags': list(FLAGS)}, 'modes': list(MODES),
                'row_policy': 'same sampled complete cases in all modes; supplied BENIGN versus known attack labels',
                'scope': 'previously consumed calibration day for development only; not final evaluation or model training'}
    write_json(OUT / 'protocol.json', protocol)
    db = sqlite3.connect(OUT / 'groups.sqlite')
    started = time.time()
    scanned = selected = valid = 0
    errors, labels, protocol_values = Counter(), Counter(), Counter()
    flag_stats = {f: {'zero': 0, 'one': 0, 'greater_than_one': 0, 'max': 0} for f in FLAGS}
    batch = Counter()
    try:
        db.execute('CREATE TABLE groups (mode TEXT, digest BLOB, benign INTEGER, attack INTEGER, PRIMARY KEY(mode,digest)) WITHOUT ROWID')
        def flush():
            if not batch:
                return
            db.executemany('INSERT INTO groups VALUES(?,?,?,?) ON CONFLICT(mode,digest) DO UPDATE SET benign=benign+excluded.benign, attack=attack+excluded.attack',
                           ((mode, digest, count if label == 0 else 0, count if label == 1 else 0) for (mode, digest, label), count in batch.items()))
            db.commit(); batch.clear()
        with zipfile.ZipFile(SOURCE) as bundle:
            members = sorted((x for x in bundle.infolist() if not x.is_dir() and x.filename.lower().endswith('.csv')), key=lambda x:x.filename)
            for member in members:
                with bundle.open(member) as raw, io.TextIOWrapper(raw, encoding='utf-8-sig', newline='') as stream:
                    reader = csv.reader(stream)
                    headers = [x.strip() for x in next(reader)]
                    if len(headers) != 88 or len(set(headers)) != 88:
                        raise ValueError('Unexpected source header')
                    base_i = [headers.index(ALIASES.get(name, name)) for name in FEATURES]
                    extra_i = [headers.index(name) for name in ('Protocol', *FLAGS)]
                    label_i, date_i = headers.index('Label'), headers.index('Timestamp')
                    for number, row in enumerate(reader, 2):
                        scanned += 1
                        if not selected_record(ARCHIVES['calibration'][1], member.filename, number, 100):
                            if scanned % 1000000 == 0:
                                write_json(OUT / 'progress.json', {'status':'running','source_rows_scanned':scanned,'selected':selected,'valid':valid,'elapsed_seconds':round(time.time()-started,1)})
                            continue
                        selected += 1
                        if len(row) != len(headers):
                            errors['column_count'] += 1; continue
                        label = row[label_i].strip()
                        if label not in FAMILIES or not row[date_i].strip().startswith('2018-12-01 '):
                            raise ValueError(f'Unexpected label or date {member.filename}:{number}')
                        try:
                            base = tuple(float(row[i]) for i in base_i)
                            extra = tuple(float(row[i]) for i in extra_i)
                        except ValueError:
                            errors['nonnumeric'] += 1; continue
                        if not all(math.isfinite(x) for x in base) or base[0] < 0 or not all(math.isfinite(x) and x >= 0 and x.is_integer() for x in extra) or extra[0] > 255:
                            errors['invalid_numeric'] += 1; continue
                        extra = tuple(int(x) for x in extra)
                        binary = int(label != 'BENIGN')
                        labels[label] += 1; valid += 1
                        protocol_values[str(extra[0])] += 1
                        for name, value in zip(FLAGS, extra[1:]):
                            stats = flag_stats[name]; stats['zero'] += value == 0; stats['one'] += value == 1; stats['greater_than_one'] += value > 1; stats['max'] = max(stats['max'], value)
                        combinations = (base, base+extra[:1], base+extra[1:], base+extra)
                        for mode, vector in zip(MODES, combinations):
                            batch[(mode, bytes.fromhex(feature_digest(vector)), binary)] += 1
                        if valid % 10000 == 0:
                            flush()
        flush()
        if scanned != audit['roles']['calibration']['rows']:
            raise ValueError('Scanned source row count differs from audit')
        results = {mode: group_summary(db, mode) for mode in MODES}
        for p, digest in hashes.items():
            if sha256(ROOT / p) != digest:
                raise ValueError(f'Dependency changed: {p}')
        if sha256(SOURCE) != protocol['source_sha256'] or sha256(AUDIT) != protocol['audit_sha256']:
            raise ValueError('Source or audit changed during scan')
        report = {'status':'complete','source_rows_scanned':scanned,'selected':selected,'valid':valid,'errors':dict(errors),
                  'labels':dict(labels),'protocol_values':dict(protocol_values),'flag_stats':flag_stats,'collision_modes':results,
                  'protocol_sha256':sha256(OUT / 'protocol.json'),'elapsed_seconds':round(time.time()-started,1)}
        write_json(OUT / 'report.json', report)
        write_json(OUT / 'progress.json', {'status':'complete','source_rows_scanned':scanned,'selected':selected,'valid':valid,'elapsed_seconds':report['elapsed_seconds']})
    except BaseException as exc:
        write_json(OUT / 'progress.json', {'status':'failed','source_rows_scanned':scanned,'selected':selected,'valid':valid,'error':repr(exc)})
        raise
    finally:
        db.close()


if __name__ == '__main__':
    main()
