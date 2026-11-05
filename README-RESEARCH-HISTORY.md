# Attack traffic classifier

Offline research project investigating how original and corrected network-flow datasets change intrusion-detection results. Requirements: [PRD](PRD-01-attack-traffic-classifier.md) and [TRD](TRD-01-attack-traffic-classifier.md).

Project-authored code is available under the [MIT License](LICENSE). Dataset and third-party software terms apply separately.

## Current checkpoint — 5 November 2026

The original/corrected 1% capture-day comparison remains the research reference; it is exploratory and is not an independent matched-flow or label-only causal study. The original source's AM/PM and timezone remain unresolved. Subsequent cross-capture evaluations and experiments expose weak or unstable transfer, high sensitivity to repeated feature groups, and uncertain TCP flag semantics. The CIC-DDoS2019 assessment has been consumed and must not be represented as a fresh holdout. The shared 27-feature reference excludes the disputed flag fields. See [sensitivity results](docs/EXPERIMENT-007-SENSITIVITY-RESULTS.md) and the [rare-flag investigation](docs/EXPERIMENT-008-RARE-FLAG-MATCH-RESULTS.md).

The [clean virtual-environment check](docs/CLEAN-ENVIRONMENT-SMOKE-2026-11-05.md) passed a synthetic run, report rebuild and two-row-per-variant score parity. The [requirement review](docs/RELEASE-REVIEW-2026-11-05.md) records current evidence and remaining restrictions. A fresh full-data run, a new independent holdout, exact original UTC chronology and corrected-data redistribution terms remain unverified. The environment reuses the host OS and Python, and transitive dependencies are not fully pinned.

Sections below retain historical results and commands; their older test counts and "next" steps describe their respective checkpoints, not the current experiment queue.

## Current implementation

The pipeline audits CSV inputs, creates chronological partitions, quarantines later feature duplicates and boundary-spanning flows, trains constant and bounded random-forest baselines, selects thresholds on validation data, and evaluates the frozen thresholds on test data. A separate family classifier reports seen/unseen limitations. Saved-model batch scoring shares the fitted pipeline.

Each immutable run contains provenance/configuration/source hashes, audit and feature exports, class inventories, predictions, metrics with Wilson intervals, per-family diagnostics, a report, resource measurements and a model card. The random forest uses identity preprocessing: no scaling or imputation is needed because required nonfinite inputs are excluded by the audit. Training never balances validation/test data.

The original/corrected exploratory **capture-day comparison is now complete** on independent deterministic 1% samples. Read [Experiment 002](docs/EXPERIMENT-002.md), [the current model card](docs/MODEL-CARD.md), or `artifacts/paired-comparison-final/report.md`. Validation recall remains poor (1.29% original / 2.55% corrected); the larger pooled test recalls (54.79% / 72.31%) are dominated by DDoS. These are descriptive population differences, not a label-correction benefit estimate.

The core audit uses the Python standard library; YAML and training require the packages listed below. The verified environment is Python **3.13.14**. The numerical dependency set is pinned in `requirements-training.txt`; this is a tested package snapshot.

## Setup and commands

From this folder in PowerShell, set up a project-local environment if needed:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-training.txt
```

Use the environment's Python in subsequent commands. The current machine already had these packages; no package installation was needed during implementation.

```powershell
python main.py audit --config configs/demo.json
python main.py run --config configs/attack-demo.yaml
python -m unittest discover -s tests -v
```

Output directories are immutable. If the example run already exists, copy its config and choose a new `output_dir` before rerunning. Paths resolve relative to the configuration file. Both JSON and safe YAML are supported; use quoted strings for timestamps in YAML.

`examples/original.csv` and `examples/corrected.csv` are invented fixtures. Their names demonstrate two adapter configurations; synthetic scores provide no evidence about CICIDS2017 corrections or detection quality.

## Corrected dataset and subset preparation

The user-approved CNS2022 archive is local at `data/cns2022/CICIDS2017_improved.zip`. The acquisition manifest records the source, retrieval time, **343,549,013 bytes** and SHA-256. A complete ZIP inventory verified all five members' CRCs and counted **2,099,976 rows**. Aggregate evidence lives in `data/cns2022/inventory.json`; no raw endpoint identifiers are exported. See [dataset decision](docs/DATASET-DECISION.md) for sources, terms and original-release blockers.

The CSVs are unsorted. Prepare a deterministic, label-independent 1-in-100 subset and sort it by event start:

```powershell
python -m attack_traffic.prepare --archive data/cns2022/CICIDS2017_improved.zip --acquisition data/cns2022/acquisition.json --output data/cns2022/subset-1pct
python main.py run --config data/cns2022/subset-1pct/config.json
```

These commands also refuse existing outputs. The generated config fixes Monday–Tuesday as training, Wednesday as validation and Thursday–Friday as testing, using UTC. It records the 27 numeric features, a 200-tree forest, depth 12, minimum leaf size 2, seed 42, one worker and a 1% validation FPR ceiling. Selection uses a hash of the archive SHA, member name and source record number; it never balances by label. The subset manifest records sampled and source population counts. This is a corrected-only preliminary experiment; the shared original/corrected feature intersection is still unverified.

Labels ending exactly ` - Attempted` map to benign under the declared policy; raw labels and attempted categories stay in the split audit. End times derive from UTC starts plus microsecond Flow Duration. A conservative feature-only duplicate policy can group distinct or conflicting-label flows; those losses remain visible. Missing attack families and low-support classes must be read alongside headline metrics. Flow-level Wilson intervals assume independence and do not resolve temporal correlation.

## Score a trusted model

Supply a CSV containing exactly the canonical allowed feature columns and optionally unique nonempty `record_id` values. The experiment's `audit/retained_features.csv` also has a `variant` column, which must be removed before scoring. Do not feed raw dataset exports directly into this interface.

```powershell
python main.py score --model artifacts/corrected-subset-1pct/models/corrected --input canonical-flows.csv --output artifacts/new-scores.csv
```

Metadata schema, environment and bundle hash are checked before loading. Only load trusted local models: joblib deserialization can execute code; a hash check does not make an untrusted artifact safe. See [scikit-learn persistence guidance](https://scikit-learn.org/stable/model_persistence.html).

## Original / corrected capture-day comparison

The original archive contains 2,830,743 nonempty flows and 288,602 all-85-fields-empty source records. The latter have no binary label; every source reference and sampling flag is retained in `data/original/subset-1pct-capture-date/preparation_exclusions.csv`. The duplicate Fwd Header Length columns are inspected positionally and omitted from inputs. Original labels use a versioned spelling/family map, while raw source strings remain in the evidence.

Original AM/PM and timezone are not recoverable from the supplied clock strings alone. The paired experiment uses capture-date boundaries `2017-07-05` and `2017-07-06`, not invented original UTC timestamps. Local uncertainty bounds conservatively quarantine possible cross-boundary flows. Within-day duplicate retention follows source order in both releases. This differs from the earlier corrected-only event-time experiment; the two experiments have separate immutable outputs.

After acquiring the archives, prepare and run from PowerShell:

```powershell
python main.py inspect-original --archive data/original/GeneratedLabelledFlows.zip --acquisition data/original/acquisition.json --output data/original/full-inventory.json
python main.py prepare-original --archive data/original/GeneratedLabelledFlows.zip --acquisition data/original/acquisition.json --output data/original/subset-1pct-capture-date
python -m attack_traffic.prepare --archive data/cns2022/CICIDS2017_improved.zip --acquisition data/cns2022/acquisition.json --output data/cns2022/subset-1pct-capture-date --temporal-basis capture_date
python -m attack_traffic.paired --original data/original/subset-1pct-capture-date --corrected data/cns2022/subset-1pct-capture-date --config configs/paired-capture-date.json --output artifacts/paired-capture-date
python main.py run --config configs/paired-capture-date.json
python main.py report --run artifacts/paired-capture-date --output artifacts/paired-comparison-final --charts --parquet
```

These artifacts already exist locally; skip completed preparation or choose new destinations to reproduce without overwriting evidence. The paired-config builder rejects mismatched feature orders/units, model settings, sampling denominators or date boundaries. The run uses separate per-release label/clock adapters and thresholds selected only on their validation data. Original and corrected cohorts are independently sampled; no row-position matching is performed. The corrected test capture was previously examined, so this is an exploratory comparison rather than a fresh prospective holdout.

Final artifacts include `comparison.csv` and `recall_comparison.png`, alongside class support/recall, provenance, audit losses, predictions, saved models and Parquet exports. Saved-model scoring exactly reproduced 8,622 original and 6,990 corrected test rows. The full suite passed 101 tests.

## Rebuild reports without training

Reports can be independently regenerated from saved validation/test predictions. The command checks row identities against the split audit, versioned labels, class support, confusion counts, frozen thresholds, metric consistency and population controls. It never calls model fitting or deserializes a model. It rejects incomplete/inconsistent evidence and publishes to a new directory while preserving the source run.

```powershell
python main.py report --run artifacts/corrected-subset-1pct --output artifacts/research-report --charts --parquet
```

Choose a fresh output directory on each run. Omit the flags for JSON/CSV/Markdown-only output. Optional dependencies are pinned in `requirements-report.txt`; they were already installed on the verified machine. In a new project environment, install them with `python -m pip install -r requirements-report.txt`.

Outputs include `report.md`, `metrics.json`, `metrics.csv`, `per_class.csv` and source hashes in `provenance.json`. The optional exports add `recall_by_family.png`, `test_confusion.png`, `splits.parquet` and `predictions.parquet`. Parquet preserves record IDs, empty category/label strings, ISO timing/uncertainty strings and float64 scores/thresholds. `comparison.csv` and the optional `recall_comparison.png` appear for a validated multi-variant run; a corrected-only report explicitly withholds a paired comparison.

Precision@K ranks the top scores even for a constant baseline that emits no alerts at its frozen threshold. It must not be mistaken for the precision of emitted alerts. The charts show test support and training support; unsupported test families retain null recalls in the class tables. Consistency checks and source hashes help detect damaged/changed evidence; they do not authenticate the dataset's ground truth or protect against a consistently rewritten artifact set.

Report regeneration loads split/prediction metadata in memory. It is verified on the current subset; full-release reporting memory use still needs a benchmark. Temporal-block comparison intervals remain future work.

## Validation-only improvement experiment

[Experiment 003](docs/EXPERIMENT-003.md) audits duplicate feature groups and compares exactly three class-weight settings on the frozen training/validation cohorts. It does not change deduplication, expand training, consult source test-result files or generate test predictions.

```powershell
python main.py audit-collisions --run artifacts/paired-capture-date --output artifacts/experiment-003-duplicate-audit
python main.py tune-weights --run artifacts/paired-capture-date --output artifacts/experiment-003-class-weights --chart
```

Both outputs already exist locally; choose new output paths to reproduce. `balanced_subsample` wins the declared joint validation rule: corrected recall improves from 2.55% to 3.59%, original recall stays 1.29%, and both observed FPRs remain below 1%. Corrected false positives fall 30→23; original false positives rise 37→38. This is a small validation gain, not a demonstrated test-accuracy improvement. Plain balanced weighting worsens corrected validation recall.

The duplicate audit confirms 86 original and 8 corrected binary-conflicting feature groups; matching feature hashes do not prove shared source-flow identity. It leaves every source disposition unchanged. All 10,902 unweighted validation predictions reproduce the reference exactly, and the full suite passes 119 tests. Source model bundles remain frozen: candidate advancement is a recommendation for further research, and the ablation does not save/deploy a replacement fitted model.

## Frozen-cohort feature experiment

[Experiment 004](docs/EXPERIMENT-004.md) adds a fixed block of eight directional interarrival statistics and four ratios, using identical cohorts and balanced subsample settings. It **retains the 27-feature reference**: original validation recall changes 1.29%→1.48%, but corrected recall falls 3.59%→0.41%. All observed FPRs stay below 1%. The extra measurements separate no existing conflicting feature groups. Baseline reproduction matches all 10,902 validation predictions; all **145 tests pass**. No new test predictions or replacement model bundles were produced.

```powershell
python main.py extract-features --run artifacts/paired-capture-date --original-archive data/original/GeneratedLabelledFlows.zip --original-acquisition data/original/acquisition.json --corrected-archive data/cns2022/CICIDS2017_improved.zip --corrected-acquisition data/cns2022/acquisition.json --output artifacts/experiment-004-feature-extract
python main.py ablate-features --run artifacts/paired-capture-date --features artifacts/experiment-004-feature-extract --output artifacts/experiment-004-features --chart
```

These outputs already exist; choose fresh destinations to reproduce. Review `artifacts/experiment-004-features/report.md` and `validation_recall.png` for the saved results. Next model work should assess training attack support under a separate frozen cohort design.

## Remaining work

The [corrected 2018 development-member inventory](docs/CORRECTED-IDS2018-DEVELOPMENT-INVENTORY.md) is complete: 5,898,350 rows, all 27 required features valid, member CRC/size/SHA verified, and 1,177 next-date benign records reported. No full archive download or model scoring occurred. Historical extraction provenance and a protected final assessment remain gates for Experiment 006.

The [regenerated 2018 release review](docs/CORRECTED-IDS2018-RELEASE-REVIEW.md) verifies archive metadata and a matching development header using only 5,314 ranged bytes. The release is a candidate for development inspection; full acquisition, row coverage and exact historical extractor provenance are not yet verified. The next slice is the 14 February member inspection, without model tuning.

The [coverage audit](docs/IDS2018-COVERAGE-AUDIT.md) found unsorted source rows, clock ambiguity and a possible export row cap; underlying capture completeness remains unproven. The [distribution/error audit](docs/IDS2018-SHIFT-AUDIT.md) reproduced every frozen evaluation confusion total and found large benign-feature shifts and extensive tied zero scores. The [next experiment plan](docs/EXPERIMENT-006-PLAN.md) prioritizes source/extractor provenance, then a controlled addition of Wednesday attack-family support with identical calibration cohorts and a newly protected assessment. No new model has been trained from these diagnostics.

The [external evaluation report](docs/IDS2018-ROBUSTNESS-RESULTS.md) evaluates the frozen balanced-subsample binary models on two CSE-CIC-IDS2018 days under a qualified cross-version protocol. Both exceed the 1% false-positive target on 15 February, and detection varies sharply by attack label. Feature equivalence and some source labels remain uncertain; these results do not establish operational readiness.

[Experiment 005](docs/EXPERIMENT-005.md) tested a larger nested, label-independent early training sample. Original validation recall rose from 1.29% to 3.81%, while corrected recall fell from 3.59% to 0.75%; the joint rule retains the baseline. The full suite passes 154 tests. See the experiment for cohort counts, the held-out feature-hash guard and limitations.

Both archives, the full original positional inventory and the qualified capture-day comparison are complete. Original UTC/AM-PM recovery remains unresolved and is explicitly represented as uncertainty rather than a fabricated event time. No personal registration details belong in config or project logs. See [original acquisition evidence](docs/ORIGINAL-ACQUISITION.md) and [adapter decisions](docs/ORIGINAL-ADAPTER.md).

The remaining release review covers exact-time limitations, temporal-block uncertainty when sufficient independent blocks are available, and clean-environment reproduction. Further model work should investigate richer independent features/projection conflicts and increased training support under protected held-out cohorts. Two test capture days do not support a reliable block comparison interval. The current result does not establish broad unseen-attack detection or a causal benefit from corrections. See the [roadmap](docs/ROADMAP.md). Real data and generated artifacts remain outside version control.
