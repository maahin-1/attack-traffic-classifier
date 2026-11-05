"""Review saved Experiment 002 artifacts without retraining or rescoring."""
import csv
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from attack_traffic.audit import _feature_safe
from attack_traffic.model import load_model

RUN = ROOT/'artifacts/paired-capture-date'
OUTPUT = ROOT/'artifacts/release-review-20261105.json'
ARCHIVES = {'original': ROOT/'data/original/GeneratedLabelledFlows.zip',
            'corrected': ROOT/'data/cns2022/CICIDS2017_improved.zip'}


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024*1024), b''):
            digest.update(block)
    return digest.hexdigest()


def load(path):
    return json.loads(path.read_text(encoding='utf-8'))


def read_rows(path):
    with path.open(encoding='utf-8-sig', newline='') as stream:
        yield from csv.DictReader(stream)


def main():
    if OUTPUT.exists():
        raise FileExistsError(OUTPUT)
    manifest = load(RUN/'manifest.json')
    quality = load(RUN/'audit/quality.json')
    inventory = load(RUN/'audit/inventory.json')
    features = load(RUN/'audit/feature_list.json')['features']
    if len(features)!=27 or len(set(features))!=27 or not all(_feature_safe(f) and 'flag' not in f.lower() for f in features):
        raise ValueError('unexpected or unsafe feature policy')
    results = {}; datasets = {x['variant']:x for x in manifest['datasets']}
    for variant in ('original','corrected'):
        dataset = datasets[variant]; prep = dataset['preparation']; acq = load(ARCHIVES[variant].parent/'acquisition.json')
        archive_hash = sha(ARCHIVES[variant])
        if archive_hash != prep['archive_sha256'] or archive_hash != acq['sha256'] or ARCHIVES[variant].stat().st_size != acq['bytes']:
            raise ValueError(f'archive mismatch {variant}')
        if dataset['input_rows'] != sum(quality[variant]['dispositions'].values()):
            raise ValueError(f'audit totals do not reconcile {variant}')
        bundle, metadata = load_model(RUN/'models'/variant)
        if metadata['feature_allowlist'] != features or bundle['feature_allowlist'] != features:
            raise ValueError(f'feature lists differ {variant}')
        dimensions = {n:bundle[n].steps[-1][1].n_features_in_ for n in ('binary_pipeline','family_pipeline')}
        if any(n != len(features) for n in dimensions.values()):
            raise ValueError(f'fitted feature dimensions differ {variant}')
        results[variant] = {'archive_sha256':archive_hash, 'archive_bytes':ARCHIVES[variant].stat().st_size,
                            'model_bundle_sha256':metadata['bundle_sha256'], 'features':len(features),
                            'fitted_feature_dimensions':dimensions, 'audit_dispositions':quality[variant]['dispositions']}
    totals = defaultdict(Counter); support = defaultdict(lambda:defaultdict(Counter)); families = defaultdict(lambda:defaultdict(Counter)); groups = defaultdict(set); cross_partition_groups = set(); date_errors = []
    for row in read_rows(RUN/'audit/splits.csv'):
        variant = row['variant']; totals[variant][row['disposition']] += 1
        if row['disposition'] != 'retained':
            continue
        partition = row['partition']; support[variant][partition][row['binary_label']] += 1; families[variant][partition][row['family']] += 1
        if row['duplicate_group_id']:
            key = (variant,row['duplicate_group_id'])
            if groups[key] and partition not in groups[key]: cross_partition_groups.add(key)
            groups[key].add(partition)
        day = row['capture_date']
        expected = 'train' if day < '2017-07-05' else 'validation' if day < '2017-07-06' else 'test'
        if partition != expected: date_errors.append(row['record_id'])
    if cross_partition_groups or date_errors: raise ValueError('Retained duplicate or date split violation')
    for variant in results:
        if dict(totals[variant]) != quality[variant]['dispositions']:
            # Zero-disposition categories may not be represented as rows.
            if any(totals[variant][k]!=v for k,v in quality[variant]['dispositions'].items()):
                raise ValueError(f'split ledger totals do not reconcile {variant}')
        if {p:dict(v) for p,v in support[variant].items()} != inventory[variant]['retained_binary_support']:
            raise ValueError(f'binary support mismatch {variant}')
        results[variant]['split_ledger_dispositions'] = dict(totals[variant])
        results[variant]['retained_binary_support'] = {p:dict(v) for p,v in support[variant].items()}
    checked = 0
    for row in read_rows(RUN/'per_class.csv'):
        if row['model'] != 'random_forest': continue
        v=row['variant']; family=row['family']; train=families[v]['train'][family]; test=families[v]['test'][family]
        if int(row['training_support'])!=train or int(row['test_support'])!=test or (row['seen_in_training']=='True')!=(train>0):
            raise ValueError(f'class support or seen flag mismatch {v} {family}')
        if not test and row['binary_detection_recall']:
            raise ValueError('unsupported test class has non-null recall')
        checked+=1
    score_evidence=load(ROOT/'artifacts/paired-verification/model-scoring.json')
    for variant in results:
        if score_evidence[variant]['test_rows'] != sum(support[variant]['test'].values()) or not score_evidence[variant]['class_and_decision_parity'] or score_evidence[variant]['maximum_absolute_score_difference']!=0:
            raise ValueError(f'historical score parity evidence mismatch {variant}')
    output={'status':'checks_passed','scope':'Experiment 002 subset artifacts; no independent holdout or new scoring',
            'variants':results,'cross_partition_retained_duplicate_groups':len(cross_partition_groups),
            'retained_capture_date_partition_errors':len(date_errors),'random_forest_family_rows_checked':checked,
            'historical_saved_model_parity':score_evidence,'feature_names':features,
            'limitations':['Original exact UTC and AM/PM unresolved', 'Corrected test previously inspected', 'Dataset redistribution terms not fully verified', 'Hash integrity is not independent dataset authentication']}
    OUTPUT.write_text(json.dumps(output,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    print(json.dumps({'status':output['status'],'variants':list(results),'family_rows_checked':checked}))


if __name__ == '__main__':
    main()
