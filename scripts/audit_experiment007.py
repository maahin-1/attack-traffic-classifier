"""Full, disk-backed source quality and feature-collision audit; no scoring."""
import hashlib
import json
import sqlite3
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from attack_traffic.experiment007_input import ARCHIVES, iter_pinned_rows
from attack_traffic.prepare import FEATURES
from attack_traffic.support_extract import feature_digest

OUT = ROOT / 'artifacts' / 'experiment-007-quality-audit'
NAMES = [x[0] for x in FEATURES.values()]


def save(path, value):
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n', encoding='utf-8')
    temp.replace(path)


def main():
    OUT.mkdir(parents=True, exist_ok=False)
    started = time.time()
    summary = {'status': 'running', 'sources': ARCHIVES, 'adapter_sha256': hashlib.sha256((ROOT / 'attack_traffic/experiment007_input.py').read_bytes()).hexdigest(), 'roles': {}}
    db = sqlite3.connect(OUT / 'groups.sqlite')
    try:
        db.execute('CREATE TABLE groups (digest BLOB PRIMARY KEY, cb INTEGER NOT NULL DEFAULT 0, ca INTEGER NOT NULL DEFAULT 0, ab INTEGER NOT NULL DEFAULT 0, aa INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID')
        for role in ('calibration', 'assessment'):
            stats = {'rows': 0, 'valid': 0, 'errors': {}, 'labels': {}, 'features': {n: {'min': None, 'max': None, 'zeros': 0, 'negative': 0} for n in NAMES}}
            summary['roles'][role] = stats
            errors, labels, batch = Counter(), Counter(), Counter()
            def flush():
                if not batch:
                    return
                db.executemany('INSERT INTO groups(digest,cb,ca,ab,aa) VALUES(?,?,?,?,?) ON CONFLICT(digest) DO UPDATE SET cb=cb+excluded.cb,ca=ca+excluded.ca,ab=ab+excluded.ab,aa=aa+excluded.aa', ((key[0], *(count if i == key[1] else 0 for i in range(4))) for key, count in batch.items()))
                db.commit()
                batch.clear()
            for record in iter_pinned_rows(ROOT / 'data/cicddos2019', role):
                stats['rows'] += 1
                if 'source_label' in record:
                    labels[record['source_label']] += 1
                if 'error' in record:
                    errors[record['error']] += 1
                else:
                    values = record['features']
                    stats['valid'] += 1
                    for name, value in zip(NAMES, values):
                        feature = stats['features'][name]
                        feature['min'] = value if feature['min'] is None else min(feature['min'], value)
                        feature['max'] = value if feature['max'] is None else max(feature['max'], value)
                        feature['zeros'] += value == 0
                        feature['negative'] += value < 0
                    index = (0 if role == 'calibration' else 2) + record['label']
                    batch[(bytes.fromhex(feature_digest(values)), index)] += 1
                if stats['rows'] % 100000 == 0:
                    flush()
                    stats['errors'], stats['labels'] = dict(errors), dict(labels)
                    summary['elapsed_seconds'] = round(time.time() - started, 1)
                    save(OUT / 'progress.json', summary)
            flush()
            stats['errors'], stats['labels'] = dict(errors), dict(labels)
            save(OUT / 'progress.json', summary)
        query = '''SELECT COUNT(*), SUM(cb+ca+ab+aa),
          SUM(CASE WHEN cb+ca+ab+aa>1 THEN 1 ELSE 0 END),
          SUM(CASE WHEN cb+ca+ab+aa>1 THEN cb+ca+ab+aa-1 ELSE 0 END),
          SUM(CASE WHEN cb+ca>0 AND ab+aa>0 THEN 1 ELSE 0 END),
          SUM(CASE WHEN cb+ab>0 AND ca+aa>0 THEN 1 ELSE 0 END),
          SUM(CASE WHEN cb+ab>0 AND ca+aa>0 THEN cb+ca+ab+aa ELSE 0 END)
          FROM groups'''
        result = db.execute(query).fetchone()
        keys = ('unique_groups', 'valid_rows', 'repeated_groups', 'rows_after_first', 'cross_day_groups', 'binary_conflict_groups', 'rows_in_binary_conflict_groups')
        summary['collisions'] = dict(zip(keys, result))
        summary['status'] = 'complete'
        summary['elapsed_seconds'] = round(time.time() - started, 1)
        save(OUT / 'report.json', summary)
        save(OUT / 'progress.json', summary)
    except BaseException as exc:
        summary['status'] = 'failed'
        summary['error'] = repr(exc)
        save(OUT / 'progress.json', summary)
        raise
    finally:
        db.close()


if __name__ == '__main__':
    main()
