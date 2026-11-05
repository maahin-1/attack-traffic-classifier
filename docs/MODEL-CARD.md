# Model card: CICIDS2017 capture-day research baselines

Version 0.2 research checkpoint, 2 November 2026. Evidence and frozen design: [Experiment 002](EXPERIMENT-002.md). This card describes the paired 1% subset run at `artifacts/paired-capture-date/`; it is not a certification of the complete PRD/TRD release.

## Current addendum — 5 November 2026

The [release evidence review](RELEASE-REVIEW-2026-11-05.md) rechecked both local archives, bundle/metadata feature contracts, capture-day split totals, retained class support and historical score-parity evidence. It also rebuilt the saved-score comparison in a new virtual environment. The original UTC/AM-PM limitation and reuse of the corrected test capture remain. Package versions beyond directly pinned dependencies may vary between environments.

Later [Experiment 007 sensitivity analysis](EXPERIMENT-007-SENSITIVITY-RESULTS.md) shows that the same consumed assessment's apparent performance can change sharply when repeated feature groups receive different weights. [Experiment 008](EXPERIMENT-008-RARE-FLAG-MATCH-RESULTS.md) found unresolved cross-release TCP flag semantics; the shared 27-feature reference described in this card excludes those flag fields. Neither analysis establishes a new independent validation or operational performance. A new independent capture is necessary before making a new generalization claim.

## Intended use and outputs

Offline study of how original and regenerated intrusion datasets change a fixed ML pipeline's measured behavior. Intended readers are learners and technical reviewers. Models do not capture packets, contact traffic endpoints, block traffic or make incident-response decisions.

Two binary random forests output uncalibrated attack scores, threshold decisions and stable local record IDs. Separate family forests provide a closed-set diagnostic. Scores must not be interpreted as calibrated enterprise-network attack probabilities. Constant majority baselines expose the trivial no-detection operating point.

## Data and feature contract

Original publisher archive SHA-256 `7bdbef286f8893f31c6db12105fa097fa5c2dcc6733179037a08129d150ea27a`; corrected CNS2022 SHA-256 `97fdb91d339e2d8cf5627f981b831e5e7e400b981c58181c451a38fd03c48883`. Acquisition references, terms and checksums remain in local manifests. Raw archives stay outside source control; no redistribution license beyond documented references is asserted.

Original 3,119,345 CSV records include 288,602 empty padding records, separately audited and excluded without a binary label. Hash sampling is label-independent and uses original source ordinals. Selected original/corrected flows: 28,234 / 20,909; retained after quality and duplicate/boundary quarantine: 22,964 / 18,866. Populations are not one-to-one matched.

The 27 features describe flow duration, directional packet counts/payload lengths, packet-length statistics, interarrival gaps and active/idle statistics. Units and aliases are explicit. IPs, ports, flow IDs, source row indices, labels, attempted categories and timing metadata are excluded. Original duplicate Fwd Header Length columns are read positionally and both omitted. Corrected attempted labels map to benign; raw labels/categories remain available in audit evidence.

## Training and time controls

Monday–Tuesday train, Wednesday validation, Thursday–Friday test. Original AM/PM/timezone remain unresolved: original UTC event fields are blank, and local uncertainty intervals conservatively bound possible starts/ends. Capture-date chronology is established; exact cross-release UTC-instant alignment is not. Flows possibly spanning partitions are quarantined. Duplicate retention uses earliest capture date and deterministic source order within a day, which may select a different representative among conflicting labels than true event order.

Both forests use 200 trees, depth 12, minimum leaf size 2, seed 42 and one CPU worker. Features are passed through unchanged after the audit excludes nonfinite required inputs. No class weighting, resampling or hyperparameter search was used. Each model's threshold maximizes validation recall under observed benign FPR <=1%, then stays frozen for testing. All test attack families are unseen during training. The corrected test capture was inspected in an earlier experiment; this paired comparison is exploratory and reuses those observations.

## Results and important failures

Validation recall is only **1.29% original / 2.55% corrected**. Pooled test recall is **54.79% / 72.31%**, with FPR **0.999% / 0.792%** and precision@100 **93% / 94%**. The descriptive differences do not isolate correction effects.

DDoS accounts for 819/830 original and 940/948 corrected true positives. Excluding DDoS, test attack recall is only **4.55% / 2.16%**. Portscan and infiltration-portscan detection are weak; rare web/botnet support cannot justify reliable class-level estimates. Closed-set attribution cannot learn absent families. A low aggregate FPR or high DDoS recall does not make these models broadly useful detectors.

Wilson intervals assume independent flows and do not address temporal correlation. Two test capture days do not justify a robust temporal-block comparison interval. Dataset capture bias, label uncertainty, source padding, same-feature conflicting labels, reconstructed populations and the particular deterministic sample all limit generalization.

## Reproduction and scoring

Config: `configs/paired-capture-date.json`. Run with `python main.py run --config configs/paired-capture-date.json`; choose a new output directory rather than overwriting a run. Rebuild reviews with the `report` command described in the README. Test scores and supports are revalidated against the split audit before report publication.

Models are stored separately under `models/original/` and `models/corrected/`. Environment, feature schema and bundle hashes are checked before trusted-local deserialization. Only load locally trusted joblib bundles. Saved-model scoring matched all 15,612 test rows exactly. The tested environment is Python 3.13.14 with pinned local dependencies; numeric/package/environment evidence is in run manifests.

Remaining release gates include the documented exact-time limitation, robust comparison uncertainty where sufficient temporal blocks become available, and a full clean-environment reproduction review. This prototype is not a production intrusion-detection system.

## Subsequent development experiment

The later [2018 cross-version evaluation](IDS2018-ROBUSTNESS-RESULTS.md) uses separately frozen balanced-subsample binary models and supplied 2018 labels. Both exceed the 1% FPR target on 15 February. The subsequent [coverage](IDS2018-COVERAGE-AUDIT.md) and [shift](IDS2018-SHIFT-AUDIT.md) diagnoses identify uncertain capture coverage, clock ambiguity, benign-feature changes and tied zero scores. These are descriptive evidence, not a new holdout or causal attribution. The version 0.2 results above still describe the original unweighted paired bundles.

[Experiment 003](EXPERIMENT-003.md) preserves these model bundles and test results. Its duplicate diagnostic confirms 86 original and 8 corrected binary-conflicting feature groups before quarantine; feature-vector equality is not flow-identity proof. A three-way validation-only ablation selects balanced subsample weighting for further research: corrected recall 2.55%→3.59%, original recall unchanged at 1.29%, with both observed FPRs below 1%. No new test results or replacement fitted bundles were produced. Most unseen validation attacks still score zero, so this small gain does not resolve the failures documented above.

[Experiment 004](EXPERIMENT-004.md) subsequently tested a fixed twelve-column extension with that weighting and identical retained cohorts. The 39-feature candidate increased original validation recall to 1.48% but reduced corrected recall to 0.41%; the joint rule retains the 27-feature research reference. All observed validation FPRs remain below 1%. Extra raw measurements resolved no existing eligible training/validation feature-group conflicts. All 10,902 baseline validation predictions exactly reproduce Experiment 003. The source bundles and test evidence described in this card remain unchanged; no replacement bundle or new test scores were produced.
