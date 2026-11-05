# Experiment 006 plan: attack-family support with a protected assessment

Status: executed on 2026-11-03; neither candidate met the advancement rule. The [coverage audit](IDS2018-COVERAGE-AUDIT.md) and [shift audit](IDS2018-SHIFT-AUDIT.md) motivated addressing measurement provenance and training-family diversity together in explicit stages. Neither more early FTP/SSH examples nor adding the twelve-column block passed prior joint validation rules. On Friday the corrected model assigns identical zero scores to 601,788 attack-labeled and 446,030 benign-labeled records; lowering a threshold cannot distinguish those ties. A threshold-only adjustment is therefore not the next model intervention.

## Stage A: establish an interpretable data contract

Before fitting, identify a pinned extraction lineage with documented packet-length, interarrival and active/idle semantics, and trustworthy capture-date coverage for the proposed assessment data. Prefer a documented regenerated release with accessible extraction code and provenance; using common extraction of both captures from PCAP is the stronger but larger alternative. Inventory first, estimate transfer/storage needs before acquisition, and treat any regenerated population/label version as a distinct experiment. Do not claim it repairs the currently examined publisher CSVs or recovers missing original AM/PM. Preserve source labels alongside any revised mappings, with row-loss accounting. Exact packet-level event alignment is not assumed.

Acceptance: known source bytes/hashes and capture dates, explicit extractor/version/configuration evidence or explicitly bounded remaining uncertainty, all 27 feature definitions mapped without identifiers, label provenance reviewed, invalid-value accounting and a coverage statement supported by source evidence. A reused CSV with matching headers alone does not pass this stage. The equal row counts and clock ambiguity remain unresolved evidence limitations until better provenance exists.

## Stage B: one controlled model intervention

Question: does introducing additional attack families into training improve later-capture detection at a threshold selected under the same 1% benign-FPR rule? For each 2017 variant compare a Monday–Tuesday reference against a candidate adding Wednesday's eligible records. Keep the canonical 27 features, balanced-subsample forest, seed, tree/depth/leaf/subsampling settings and identity preprocessing fixed. Add all eligible Wednesday classes using a fixed label-independent source sample; do not add attacks alone. Report the changed class mix, sample size and family support: this is a training-population intervention, not an isolated causal estimate of attack diversity.

Use the same Thursday 2017 calibration population and calibration rule for both candidates; reconstruct cohorts under explicit capture-date timing/boundary rules, preserve source ordinals, and block training-to-calibration feature-group leakage with an exclusion ledger. This deliberately changes the previous train/validation boundary and must be a new immutable run. Thursday 2017 and any Friday 2017 or February 2018 diagnostics have already been examined, so they are exploratory evidence only. Do not call a score on them a fresh final test. Freeze both fitted bundles, calibration thresholds, cohort/schema/environment hashes and reporting policy before final assessment.

## Stage C: one new final assessment

Choose and fix a separate unexamined capture or independently sourced block after Stage A. Prefer a different operational environment where permissible; an additional day from the same 2018 synthetic testbed supports only a narrower research-capture claim. Do not silently choose favorable days or use 15/16 February again as the final test. Record source identities, sampling/exclusion policy, source-label mapping, feature-collision reporting and byte hashes before outcomes. Coverage and semantic evidence gates apply before scoring. The final source is intentionally not yet designated as available or verified.

Primary comparison: report both candidate/reference per-day recall and FPR at frozen thresholds, with TP/FP/TN/FN, precision, support, family slices and zero-score overlaps. A candidate advances only if all designated assessment blocks meet observed FPR <=1%, mean block recall strictly improves by more than 1e-12, and no block recall regresses beyond 1e-12; no threshold or candidate revision after outcomes. Report failures and low-support cases. Correlated flows, source-label errors and limited independent blocks restrict inference; numerical pass is a research advancement decision, not deployment approval. If this final assessment informs another change, acquire a further protected assessment for that model.

## Immediate next action

Research the provenance, schema and download sizes of a documented regenerated 2018 release as a candidate for Stage A, without consuming new model outcomes. Do not start a larger training run until that contract and a future assessment route are concrete. The current models, audits and external results remain the reference evidence.

This source review is now complete: see [regenerated release review](CORRECTED-IDS2018-RELEASE-REVIEW.md). Remote metadata confirms a 10.43 GB archive and a matching 27-feature development header. The selected next slice is development-member acquisition and full row/coverage inspection; historical extractor linkage and an independent final assessment remain open gates.

That development slice is complete: [full-member inventory](CORRECTED-IDS2018-DEVELOPMENT-INVENTORY.md) verifies 5,898,350 rows, member CRC/size/SHA and all 27 required numeric fields. It also identifies cross-date rows and source-order disorder, requiring explicit capture-date handling in any preparation. No model has been trained/scored on this member. Next resolve the historical-extractor evidence or declare bounded cross-version assumptions, then specify a development preparation and a protected assessment source before Stage B fitting.

## Development preparation and extractor scope

For the corrected 14 February member, use the release's documented UTC timestamps and the half-open interval from 14 February 00:00 UTC to 15 February 00:00 UTC. Preserve ZIP member and CSV record ordinal for identity and audit. A flow is eligible for that day when its parsed start is in the interval and its end, computed as start plus flow duration in microseconds, is before the upper boundary. Quarantine starts outside the interval and flows that touch or cross its upper boundary. Record invalid timestamps, durations and required features separately. This conservative boundary rule keeps next-date and spanning traffic out of the development cohort. It applies only to this corrected UTC source. Original 2017 still uses capture-date membership and its existing uncertainty rules.

Use the 27 canonical inputs with identity preprocessing. Retain raw labels and attempted categories for accounting. Map `BENIGN` and supported attempted categories to benign, and supported non-attempted attack labels to attack. Treat unresolved labels and label/category inconsistencies as preparation errors requiring review. Preserve feature-vector matches for reporting unless there is evidence of a shared flow. A source ordinal is a reproducibility key and never an ordering signal for a time split.

The existing inventory accounts for 5,898,350 rows. The start-date rule identifies 1,177 next-date benign rows and leaves 5,897,173 start-date candidates, including 5,802,976 proposed benign and 94,197 attack rows. These are upper bounds on eligibility until start-plus-duration checks are run row by row. The audited development member remains reserved for schema, coverage and distribution diagnostics.

The authors document the modified CICFlowMeter lineage, timeout settings and UTC timestamp output. The public material reviewed leaves the archive-producing commit unidentified. Treat compatible names and expected units as a bounded cross-version assumption for exploratory diagnostics. Require documented field semantics for any protected assessment and describe differences in extraction and labeling as part of the comparison. A code snapshot can pin a future reproduction, while its historical relationship to the published archive remains unresolved. [Reproduction instructions](https://github.com/GintsEngelen/CNS2022_Code) · [Extractor documentation](https://intrusion-detection.distrinet-research.be/CNS2022/Tools_Documentation.html)

Stage B fitting remains gated on a protected assessment source with verified provenance and a frozen preparation policy. The next local check is the row-level boundary ledger, followed by source selection and verification for the protected assessment.

The full boundary scan reconciled 5,898,350 records. It found 1,177 starts outside the day and 16 additional flows whose computed end reached the day boundary. All 1,193 exclusions carry the source label `BENIGN`. The remaining 5,897,157 rows comprise 5,802,960 proposed benign and 94,197 attack rows under the reviewed label policy. The scan verified the inventoried member fingerprint before and after reading, and the ledger has one unique source ordinal per exclusion. See `artifacts/corrected2018-boundary-summary.json` and `artifacts/corrected2018-boundary-ledger.csv`.

## Protected assessment candidate

CIC-UNSW-NB15 is the leading candidate. Its underlying packets were generated at the UNSW Canberra cyber range, a separate capture environment from CICIDS2017 and CSE-CIC-IDS2018. UNB regenerated flow features with CICFlowMeter and documents how it matched flows to the original ground truth, dropped ambiguous matches and assigned remaining flows to benign. [Original capture provenance](https://research.unsw.edu.au/projects/unsw-nb15-dataset) · [UNB regeneration and labeling method](https://www.unb.ca/cic/datasets/cic-unsw-nb15.html)

Inspect `CICFlowMeter_out.csv` first. UNB describes this file as the extracted flow population before the separate 80:20 sampling step. Verify the file identity and hash, all 27 feature definitions and units, label mapping and timestamp/block support before designating it as the assessment source. The publisher download form returned a server error during review, so access and schema remain pending. [Publisher download portal](https://cicresearch.ca//CICDataset/CIC-UNSW/)

The publisher portal still reports a server error. A bounded check of the public mirror at commit `8b5e371bf1cfb32683a958f62acacc6be19b5c58` found 84 unique column names, including all 27 required names, and AM/PM timestamps in January and February 2015. The mirror reports a size of 1,914,305,081 bytes and SHA-256 `025a94239f29521e154be3a65d65268404d4c58600b66b94a4235eae87dbd8b5`. Its checksum identifies the mirror snapshot. Producer revision, timestamp timezone and byte equivalence to the publisher copy remain open. [Pinned mirror file](https://huggingface.co/datasets/bencorn/CIC-UNSW-NB15/blob/8b5e371bf1cfb32683a958f62acacc6be19b5c58/CICFlowMeter_out.csv)

The full mirror download matches the pinned SHA-256 and byte count. All 3,540,241 rows have parseable timestamps, valid widths, finite required values and nonnegative duration. All ten label counts agree with UNB's full CICFlowMeter column, including 3,450,658 benign and 89,583 attack-labeled rows. The three observed source clock dates each contain both classes.

| Source clock date | Benign | Attack |
| --- | ---: | ---: |
| 22 January 2015 | 1,751,442 | 14,480 |
| 17 February 2015 | 478,524 | 20,366 |
| 18 February 2015 | 1,220,692 | 54,737 |

The adjacent February dates may belong to a single capture session, and the timezone and capture boundaries remain unresolved. At this point, the checks supported further inspection; the execution record below documents the qualified assessment decision and results. Evidence is in `artifacts/cic-unsw-nb15-mirror-inventory.json` and `data/cic-unsw-nb15-mirror/acquisition.json`. [UNB label totals and extraction description](https://www.unb.ca/cic/datasets/cic-unsw-nb15.html)

## Experiment 006 execution record (2026-11-03)

The protocol and assessment fingerprint were frozen in `artifacts/experiment-006-protocol.json` before model fitting. The 27-field CIC-UNSW-to-canonical crosswalk is recorded in [CIC-UNSW feature crosswalk](CIC-UNSW-FEATURE-CROSSWALK.md). Definitions and units are supported by CICFlowMeter's published field list and implementation; the archive-producing revision and timestamp timezone remain unknown.

Stage B fit and froze four forests in `artifacts/experiment-006-stage-b/`. Each reference trained on the existing label-independent 1% Monday–Tuesday source sample; each candidate added the eligible Wednesday sample. Each pair used the same deduplicated Thursday calibration cohort for its variant, with thresholds frozen under observed benign FPR <=1%. Thursday had appeared in previous model work, so these are calibration results only. On Thursday, the original candidate detected none of 18 attacks at threshold 0.754373; the corrected candidate detected 117/269 attacks at threshold 0.061953 with 0.982% observed FPR. No model was selected from these calibration outcomes.

Stage C scored every row of the pinned CIC-UNSW mirror under the frozen models and grouping policy. Results are in `artifacts/experiment-006-stage-c/report.md`; structured counts, labels, collisions, score digests and provenance are in `metrics.json` and `manifest.json`. All 3,540,241 rows reconciled with the inventory and had no invalid required features. January 22 was one source-clock block; February 17–18 were pooled as a second block because their session boundary is undocumented. The feature audit found 1,721,199 repeated rows after each feature group's first appearance, 65,335 repeated feature groups, and 796,806 repeats crossing the two blocks. This limits how independently the blocks can be interpreted.

Neither candidate advances under the frozen rule:

| Variant | Candidate recall: Jan 22 / February block | Candidate FPR: Jan 22 / February block | Decision |
| --- | --- | --- | --- |
| Original | 0.00% / 0.0053% | 0.00023% / 0.00018% | Do not advance; detection collapses at the frozen threshold. |
| Corrected | 16.22% / 16.17% | 2.03% / 2.35% | Do not advance; recall rises, but both blocks exceed the 1% FPR ceiling. |

These are cross-dataset research results on the pinned mirror, not publisher-authenticated performance claims. Do not retune thresholds or revise these models using this consumed assessment. The next model change needs a new experiment and another protected capture.

The postmortem is complete in `artifacts/experiment-006-postmortem/`. It reproduces the Stage C score digests and collision totals, finds 5,356 repeat rows with conflicting binary labels across 723 exact feature groups, and shows both candidates' score distributions by block and label. The original candidate's threshold lies far above almost all CIC-UNSW scores. The corrected candidate assigns benign records score mass above the threshold, explaining its FPR failure. Treat these as diagnostics for a future study, not as permission to adjust either threshold on this consumed source.

The proposed next step is target-domain threshold transfer on a new two-day source, with Experiment 006 model weights unchanged. See [Experiment 007 discovery](EXPERIMENT-007-DISCOVERY.md) for candidate-source tradeoffs and the provisional protocol. CIC-DDoS2019 is the preferred source. Its official registration form loads, but the browse page requires registration; the day-to-attack mapping, archive size and hashes remain unverified. No additional data was downloaded.
