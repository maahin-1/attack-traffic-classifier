"""Reproduce the synthetic fixture, report and saved-model scores in this interpreter."""
import csv
import json
import math
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT/'artifacts/clean-release-check-20261105'
RUN = ROOT/'artifacts/clean-release-fixture-20261105'
REPORT = ROOT/'artifacts/clean-release-report-20261105'


def execute(*args):
    result = subprocess.run([sys.executable, *map(str, args)], cwd=ROOT, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(f'{args}: {result.stdout}\n{result.stderr}')
    return result.stdout.strip()


def read_csv(path):
    with path.open(newline='', encoding='utf-8') as stream:
        return list(csv.DictReader(stream))


def main():
    if sys.prefix == sys.base_prefix:
        raise RuntimeError('A virtual environment is required')
    EVIDENCE.mkdir(parents=True, exist_ok=False)
    config_path = ROOT/'configs/attack-demo.yaml'
    config = yaml.safe_load(config_path.read_text(encoding='utf-8'))
    for dataset in config['datasets']:
        dataset['files'] = [str((config_path.parent/path).resolve()) for path in dataset['files']]
    config['output_dir'] = str(RUN)
    generated_config = EVIDENCE/'config.json'
    generated_config.write_text(json.dumps(config, indent=2)+'\n', encoding='utf-8')
    evidence = {'interpreter':sys.executable, 'python':sys.version, 'prefix':sys.prefix,
                'base_prefix':sys.base_prefix, 'pip_freeze':execute('-m','pip','freeze').splitlines(),
                'pip_check':execute('-m','pip','check'), 'status':'running'}
    (EVIDENCE/'progress.json').write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    evidence['run_command_output'] = execute('main.py','run','--config',generated_config)
    evidence['report_command_output'] = execute('main.py','report','--run',RUN,'--output',REPORT,'--charts','--parquet')
    predictions = read_csv(RUN/'predictions.csv')
    features = read_csv(RUN/'audit/retained_features.csv')
    parity = {}
    for variant in ('original', 'corrected'):
        expected = {r['record_id']:r for r in predictions if r['variant']==variant and r['model']=='random_forest' and r['partition']=='test'}
        selected = [r for r in features if r['variant']==variant and r['record_id'] in expected]
        if not expected or len(selected)!=len(expected):
            raise ValueError(f'missing or duplicate scoring rows for {variant}')
        input_path = EVIDENCE/f'{variant}-features.csv'
        with input_path.open('w',encoding='utf-8',newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=['record_id','flow_duration','packet_count'])
            writer.writeheader(); writer.writerows({k:r[k] for k in writer.fieldnames} for r in selected)
        score_path = EVIDENCE/f'{variant}-scores.csv'
        execute('main.py','score','--model',RUN/'models'/variant,'--input',input_path,'--output',score_path)
        actual = read_csv(score_path)
        if len(actual)!=len(expected) or {r['record_id'] for r in actual} != set(expected):
            raise ValueError(f'scored record mismatch for {variant}')
        for row in actual:
            ref = expected[row['record_id']]
            if not math.isclose(float(row['attack_score']),float(ref['attack_score']),rel_tol=0,abs_tol=1e-14):
                raise ValueError(f'score mismatch for {variant}')
            if any(row[k]!=ref[k] for k in ('prediction','class_prediction','threshold','model_id')):
                raise ValueError(f'prediction metadata mismatch for {variant}')
        parity[variant] = {'test_rows':len(actual), 'max_abs_tolerance':1e-14, 'matched':True}
    evidence.update({'status':'complete', 'parity':parity, 'charts_and_parquet_requested':True,
                     'note':'synthetic fixture only; installed transitive dependency versions are recorded'})
    (EVIDENCE/'report.json').write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    (EVIDENCE/'progress.json').write_text(json.dumps({'status':'complete'})+'\n',encoding='utf-8')
    print(json.dumps({'status':'complete','parity':parity}))


if __name__ == '__main__':
    main()
