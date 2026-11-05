# Experiment 002: original / corrected capture-day comparison

Design recorded on 2 November 2026 after preparation/split inventories and before computing this experiment's original or corrected model scores. This is exploratory: the corrected capture's test results were already examined in Experiment 001. No hyperparameters or threshold policy are changed in response to those test results.

## Frozen population and controls

Original snapshot SHA-256: `7bdbef286f8893f31c6db12105fa097fa5c2dcc6733179037a08129d150ea27a`. Corrected CNS2022 SHA-256: `97fdb91d339e2d8cf5627f981b831e5e7e400b981c58181c451a38fd03c48883`.

The original archive has 3,119,345 CSV records: 2,830,743 nonempty flows and 288,602 all-empty 85-field records. Those empty records are excluded as source padding, never assigned a binary label. The preparation ledger lists every excluded source ordinal and hash-selection status. Of the selected original records, 28,234 are flows and 2,838 are empty source records. Unsampled flows: 2,802,509. The corrected source has 2,099,976 flows and its independent sample has 20,909 records.

Selection: identical BLAKE2b-64 selector at denominator 100 over each release's archive SHA, member name and original CSV record number. This makes two independently selected populations, not a matched cohort or equal class-balanced samples. Source padding removal does not shift ordinals. Both subsets have a 50,000 selected-flow cap.

Feature controls: the same ordered 27 numeric flow statistics, units and explicit four header aliases; no identifiers, ports, labels, attempted category or timestamps enter model inputs. Both copies of original Fwd Header Length are inventoried and omitted. All duplicate source copies are textually equal in this archive; the adapter still reads them positionally.

Model: constant majority baseline and one random forest with 200 trees, depth 12, minimum leaf size 2, seed 42, one CPU worker, no class weighting/resampling and identity preprocessing. Family attribution uses a separate forest trained only on the training partition. Original label spellings have versioned aliases; corrected attempted labels map to benign while raw distinctions remain metadata.

## Timing contract and audit

The original export loses AM/PM and has no verified timezone. It does not support an honest exact-UTC experiment. This qualified comparison therefore matches **capture dates**, with boundaries `2017-07-05` and `2017-07-06`: Monday–Tuesday train, Wednesday validation, Thursday–Friday test. Day/month parsing is checked against source filenames and the documented capture week. No labels are used to infer time.

Original UTC event_start/end stay blank. Both possible local 12-hour starts and the entire minute/second precision bin form conservative bounds. End upper bounds add duration; potential partition-crossing rows are quarantined. Corrected UTC timestamps stay available as observed metadata. This policy meets capture-day chronology, not the stronger proposed identical-UTC-instant contract; that limitation remains open.

Feature duplicates retain the earliest eligible capture day, then deterministic prepared source member/record order. The same policy applies to both releases. It prevents duplicate groups crossing partitions but does not establish earliest true events within a day. Raw- and binary-label conflicts are counted. This differs from Experiment 001's event-time ordering and can change which same-day conflicting-label representative survives.

| Variant | Selected flows | Retained | Excluded numeric quality | Quarantined |
| --- | ---: | ---: | ---: | ---: |
| Original | 28,234 | 22,964 | 2 | 5,268 |
| Corrected | 20,909 | 18,866 | 0 | 2,043 |

Original quarantine: 5,254 later feature duplicates plus 14 possible boundary-crossing flows. Corrected quarantine: 2,043 later feature duplicates. Conflicting binary-label duplicate rows: original 676; corrected 137. These losses are part of the experiment population, not hidden cleaning.

| Variant | Partition | Benign | Attacks |
| --- | --- | ---: | ---: |
| Original | Train | 8,306 | 99 |
| Original | Validation | 3,916 | 2,021 |
| Original | Test | 7,107 | 1,515 |
| Corrected | Train | 6,837 | 74 |
| Corrected | Validation | 3,240 | 1,725 |
| Corrected | Test | 5,679 | 1,311 |

Both variants satisfy binary training/validation support. Training attack families are FTP-Patator and SSH-Patator; later families remain unseen. Rare families absent from sampled test have null recall. No revision of these partitions will be based on model test scores.

## Evaluation and reproduction

Each model's threshold maximizes validation attack recall under observed benign FPR <=1%, with fewer-alert/higher-threshold tie rules. Thresholds are then frozen before test scoring. Report confusion counts, recall, FPR, precision, average precision, pooled precision@100, flow-level Wilson intervals, unseen-family detection and training/test support. Validation and test remain imbalanced.

The two-day test period is insufficient for a reliable temporal-block comparison uncertainty claim. Wilson intervals assume independent flows and do not account for capture-day correlation. No production-network or daily alert-capacity claim is made. Differences include flow reconstruction, labels, population support and sampling; no label-only causal effect is estimated.

Frozen run config: `configs/paired-capture-date.json`. Inventory evidence: `artifacts/paired-capture-date-inventory/`. Run:

```powershell
python main.py run --config configs/paired-capture-date.json
python main.py report --run artifacts/paired-capture-date --output artifacts/paired-comparison-report --charts --parquet
```

Outputs are immutable. Results will be recorded separately after this frozen design.

## Observed results — no retuning

The validation operating points have low attack recall: **1.29% original** and **2.55% corrected**, under observed validation FPRs 0.945% and 0.926%. The selector's `useful=True` means only that some attacks were detected under the ceiling; it does not establish operational usefulness. The majority baselines emit no alerts at their permitted operating points.

| Random forest metric | Original | Corrected |
| --- | ---: | ---: |
| Frozen validation-selected threshold | 0.01625 | 0.0075 |
| Test recall | 54.79% | 72.31% |
| Test FPR | 0.999% | 0.792% |
| Test precision | 92.12% | 95.47% |
| Pooled test precision@100 | 93% | 94% |
| Test average precision | 0.6242 | 0.7618 |
| Test TP / FP / TN / FN | 830 / 71 / 7,036 / 685 | 948 / 45 / 5,634 / 363 |

The observed pooled recall difference is +17.53 percentage points and FPR difference is -0.207 percentage points for the corrected population. These are descriptive differences between independently sampled, differently constructed populations with different class support. They are not estimates of a label-correction benefit or deployment improvement.

DDoS dominates the detections: **819 of 830** original true positives and **940 of 948** corrected true positives. Original Portscan detects 10/206; corrected Portscan detects 1/95, and corrected infiltration-portscan detects 4/268. Without DDoS, binary recall is only **11/242 (4.55%) original** and **8/371 (2.16%) corrected**. Botnet support is 18 original / 7 corrected; web-brute-force support is 11 / 1. The one-record corrected web result cannot support a reliable family claim. All test attack families were absent from training, and their closed-set family attribution recall is zero.

Saved-model scoring reproduced all **8,622 original** and **6,990 corrected** test records with zero absolute score difference and identical decisions, thresholds and class predictions. Evidence: `artifacts/paired-verification/model-scoring.json`. Measured audit/training/evaluation wall time was 10.936 seconds, with a Windows process lifetime peak working set of 244,535,296 bytes (233.2 MiB); acquisition, full inventory, preparation and interpreter/import startup are outside that pipeline timer.

Final review artifacts: `artifacts/paired-comparison-final/report.md`, `metrics.csv`, `comparison.csv`, `per_class.csv`, `recall_comparison.png`, `splits.parquet`, `predictions.parquet`, and source hashes in `provenance.json`. Reports were regenerated from saved predictions without model fitting. The complete suite passed 101 tests; capture-date chart/export tests also passed after the final visualization change.

Interpretation: the data-version comparison now works and exposes substantial population/label ambiguity, but the classifier generalizes poorly to most unseen attack families. This completes the qualified capture-day comparison, while exact UTC-instant chronology and robust temporal-block uncertainty remain unresolved. No production-readiness or broad detection-quality claim is justified.
