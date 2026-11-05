# TRD 01: Attack traffic classifier

Version 1.0 | 2 November 2026 | Implements [PRD 01](PRD-01-attack-traffic-classifier.md)

## 1. Technical scope and architecture

Implement a CPU-based batch pipeline in Python using pandas or chunked CSV readers, NumPy, scikit-learn, Matplotlib and a configuration parser. Pin tested dependency versions when implementing; this specification does not assert a tested package combination.

Pipeline: local dataset → release adapter → schema/quality audit → time partition → training-only preprocessing → classifier → frozen-threshold scoring → comparison report.

Suggested modules: `ingest`, `schema`, `clean`, `split`, `features`, `train`, `evaluate`, `compare`, `report`. Keep dataset adapters separate because original and corrected schemas can differ. No service or database is needed for the MVP.

## 2. Data contracts and provenance

| Entity | Required fields and validation |
| --- | --- |
| Dataset manifest | Variant, release identifier, source URL, retrieval time, file SHA-256, schema fingerprint and license/reference |
| Flow metadata | Stable local record ID, source file, event start/end time where available, source label and mapped labels |
| Features | Allowlisted numeric flow statistics; unique canonical names and documented units |
| Split record | Record ID, partition, exclusion reason, temporal boundaries and duplicate-group ID |
| Prediction | Record ID, model ID, attack score, threshold decision, class prediction and partition |

Use metadata only for joining, splitting and audit. Never pass metadata through an automatic numeric-column selection. Preserve original labels alongside binary `0=benign, 1=attack` and a versioned attack-family mapping. Retain attempted/effective distinctions in the detailed report. Unexpected labels fail validation until mapped explicitly.

The [correction documentation](https://intrusion-detection.distrinet-research.be/WTMC2021/tools_datasets.html) points to later work; choose a release deliberately and keep the original-versus-selected-correction comparison identifiable. A change of release creates a new experiment lineage.

## 3. Cleaning and leakage prevention

Normalize column whitespace and names. Parse timestamps using declared format and timezone assumptions. Count malformed values, NaN, infinity and invalid durations by variant, class and partition. For the primary experiment, exclude rows with nonfinite required model features; record losses rather than silently dropping them.

Remove source/destination IP, all port fields, timestamp, flow ID, row index and every label-derived field from model inputs. Retain protocol only if it is a documented flow property and justify its use. Assert the feature allowlist before training and inference.

Hash canonical feature records for duplicate detection. Keep duplicate groups from crossing partitions: quarantine later copies under a documented policy and publish counts. Do not balance or oversample validation/test data. If using class weighting, apply it only during fitting.

## 4. Split and experiment design

1. Build an inventory of time coverage and class support before fitting. Set explicit boundaries in configuration, using earlier contiguous periods for training, a subsequent period for validation and the latest period for testing.
2. Assign flows by event start time and quarantine those spanning a partition boundary where end times are known. Record any incomplete timing information.
3. Fail if training or validation lacks the binary support needed for fitting or threshold selection. Revise boundaries using only the inventory, then freeze them before examining test scores.
4. Report attack-family training support. Classes absent from training are unseen; do not imply a closed-set model can learn them. Report binary recall on unseen attacks separately from family attribution. Classes absent from test have recall `null`.
5. Fit a majority/constant baseline and a bounded random forest, initially 200 trees with configured depth, minimum leaf size, seed and worker count. Tune only a small declared validation grid.
6. Use identical feature intersections, boundaries and model settings across data variants. Keep variant-specific preprocessing fitted separately on its training data.

Regenerated flows may not have a one-to-one original match. The main comparison is therefore a pipeline/data-version comparison. A label-only analysis is optional and must use a verified matched cohort with unmatched counts and mapping evidence. Never join solely on unstable row positions.

## 5. Scores, metrics and threshold policy

For binary training, attack score is `P(attack)`. For multiclass training, derive it as `1-P(benign)` by looking up the class index. Do not assume column 1 is always the malicious class.

Select the threshold with highest validation attack recall among thresholds meeting the proposed 1% benign FPR ceiling; ties prefer fewer alerts, then higher threshold. If the ceiling yields no useful detection, report an infeasible operating point and the baseline rather than relaxing it silently.

Freeze the threshold before final testing. Report FPR, recall, precision, PR-AUC, confusion counts, per-class recall and support, and precision@100 on pooled test records. Daily precision@100 is additional only if timestamps support daily grouping. Stable ID breaks tied scores. Include uncertainty intervals for FPR/recall; use temporal-block resampling for comparison uncertainty where sufficient blocks exist.

Observed daily false alerts require actual day coverage. A scenario of 10,000 benign flows/day and 1% FPR implies 100 false alerts/day; label this arithmetic as hypothetical, not measured capacity. Unsupported classes and empty metric denominators must be visible.

## 6. Proposed CLI and artifacts

Interfaces below are implementation contracts, not existing commands:

```text
python main.py run --config configs/attack.yaml
python main.py score --model artifacts/model --input flows.csv --output scores.csv
```

Config fields: dataset paths/releases, schema mappings, time cutoffs, label map, feature allowlist, deduplication policy, seed, resource limits, model grid, FPR target and alert budget.

Each immutable run directory contains `manifest.json`, `config.yaml`, `splits.parquet`, `quality.json`, feature list, fitted pipeline, `metrics.json`, per-class/comparison CSVs, predictions, recall chart and `report.md`. Save model and preprocessing as one versioned bundle. Load only trusted local serialized artifacts; reject schema/version mismatch before scoring.

## 7. Nonfunctional requirements and failure handling

- Stream ingestion; avoid holding both variants and duplicate full copies in memory. Provide a deterministic subset profile and a full-data profile, clearly named.
- Record hardware, peak resident memory, wall time, row counts and throughput. CPU-only operation is required; no unverified speed promise.
- Runs are deterministic at a pinned environment/seed to documented numeric tolerance. Reports must reconstruct without retraining from saved scores.
- Invalid paths, unexpected columns/labels, missing time fields or incomplete artifacts return a nonzero exit code and actionable message. Never turn missing scores into benign predictions.
- No packet capture or outbound connection to dataset IPs. Keep data and sensitive identifiers out of public reports and version control.

## 8. Verification and traceability

| PRD IDs | Test and required evidence |
| --- | --- |
| AT-P01, AT-P05 | Manifest/hash checks; comparison identifies both populations and release versions. |
| AT-P02 | Identifier sentinel columns cannot enter the allowlist; fitted feature names pass the exclusion assertion. |
| AT-P03 | Synthetic boundary-spanning flows and duplicate groups cannot cross partitions; saved split audit passes. |
| AT-P04 | Fixture with an unseen attack class yields separate detection recall and no false claim of trained family coverage. |
| AT-P06 | Hand-computed confusion matrix, tied top-K scores, zero benign support and partial-day coverage produce correct metrics/labels. |
| AT-P07 | Clean-environment smoke run on a small fixture creates all required artifacts; saved-model scoring agrees with original scores. |

Delivery order: adapters/audit → splits/features → baseline/threshold → comparisons → report/reproduction. Release requires passing tests, completed data accounting and a model card explaining domain limits; benchmark superiority is not a release prerequisite.
