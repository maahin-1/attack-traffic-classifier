# Experiment 004: frozen-cohort directional-IAT feature experiment

Design recorded on 2 November 2026 before extracting the additional measurements or fitting either feature candidate. This is exploratory development on an already examined capture. No new test evaluation or future-performance claim is included.

## Question and frozen controls

Does a small, explicitly defined feature block improve validation attack recall under the existing observed 1% FPR ceiling, on the exact same retained cohorts? Separately, do the additional independent measurements distinguish any of the conflicting 27-feature groups?

Source run: `artifacts/paired-capture-date/`. Source archives remain the pinned original and CNS2022 releases. Original SHA-256: `7bdbef286f8893f31c6db12105fa097fa5c2dcc6733179037a08129d150ea27a`. Corrected SHA-256: `97fdb91d339e2d8cf5627f981b831e5e7e400b981c58181c451a38fd03c48883`.

All retained row IDs, row order, source labels, capture-day partitions and duplicate dispositions remain frozen. Original train/validation rows: 8,405 / 5,937. Corrected train/validation rows: 6,911 / 4,965. No later duplicates are restored and no new grouping policy is applied to model fitting. Sample expansion and deduplication changes require separate experiments.

The extractor joins original raw records by saved source member/CSV ordinal, reads positional original columns without collapsing the repeated header, checks source labels and the existing 27-feature digest, and exports no endpoint identifiers. It handles the corrected archive through its own explicit adapter. Only training/validation eligible rows are interpreted; test-only members are not read as CSVs and test-row labels/features are skipped. Whole-archive byte hashes may be read solely for provenance.

## Fixed feature block

The candidates are exactly:

1. `baseline27`: the existing ordered 27 measurements.
2. `expanded39`: those same 27 values plus these twelve columns in a fixed order.

| Additional measurement | Count | Units / definition |
| --- | ---: | --- |
| Fwd IAT Mean, Std, Max, Min | 4 | Microseconds between packets in the forward direction |
| Bwd IAT Mean, Std, Max, Min | 4 | Microseconds between packets in the backward direction |
| Forward packet fraction | 1 | Forward count / (forward + backward count) |
| Forward payload-byte fraction | 1 | Forward payload bytes / (forward + backward payload bytes) |
| Forward payload bytes per packet | 1 | Forward payload bytes / forward packet count |
| Backward payload bytes per packet | 1 | Backward payload bytes / backward packet count |

Zero denominators map to zero under an explicit deterministic rule. Inputs must be finite and nonnegative. Invalid extra measurements on any retained training/validation row block the entire expanded experiment; rows must not be silently dropped to create a more favorable population. Such a failure publishes quality diagnostics and requires an explicit new preparation decision before fitting. Invalid quarantined diagnostic rows cannot be treated as resolved collisions.

The eight raw directional-IAT fields have matching names and documented packet-gap units in both release lineages; reconstructed flows may still change their values/distributions. The four derived features may make relationships easier for bounded-depth trees but cannot separate two records identical in all 27 primitive values. There is no label, port, address, flow ID, timestamp, source ordinal or attempted-category input. The feature-definition review is `docs/FEATURE-BLOCK-004.md`.

## Diagnostic versus model population

Collision refinement is descriptive and restricted to the training/validation eligible population, including retained representatives and their later duplicate copies. It compares the 27-feature grouping against the grouping refined by the eight new raw measurements. Derived-only transformations cannot split an exact 27-feature tie. Report eligible records, conflict-group counts, minority-label bounds, unchanged/resolved groups and any incomplete measurements, separately for each release.

This diagnostic cannot restore records, change training/evaluation membership, choose different raw fields, relabel cases or select a model. Saved source timestamps/metadata help distinguish projection equality from event identity; no causal or true-duplicate identity claim is made.

## Fixed fitting, selection and advancement

Both candidates use the Experiment 003 advancement setting `class_weight='balanced_subsample'`: 200 trees, depth 12, minimum leaf size 2, seed 42, one worker and identity preprocessing. No class weighting, model-family or hyperparameter search occurs here. The same settings and block are used on both data variants.

Retain Random Forest `max_features='sqrt'` in both candidates. This same policy considers five candidate columns per split for 27 inputs and six for 39; the feature intervention therefore includes the dimension-dependent behavior of the unchanged subsampling policy. This detail is disclosed before results, rather than attributed solely to the semantics of individual added columns. Baseline validation scores must reproduce Experiment 003's balanced-subsample reference.

Each candidate/variant selects a threshold on its frozen validation records using the existing highest-recall rule under observed FPR <=1%, with fewer-alert/higher-threshold ties. Joint selection maximizes unweighted mean release validation recall, then minimizes mean FPR, then prefers the baseline on a complete tie. Both releases must satisfy the ceiling and complete successfully. The expanded candidate advances only with strict mean recall improvement beyond 1e-12 and no per-variant recall regression beyond 1e-12. Otherwise retain the 27-feature reference. All candidate outcomes and failures remain visible.

No source test-result files are used for fitting, threshold selection or advancement. No new test scores are produced. The already inspected capture does not become an untouched holdout through new features, a seed change or a renamed experiment.

## Artifacts and acceptance

Extraction: `artifacts/experiment-004-feature-extract/`, with joined extra features, raw-unit definitions, invalid-value diagnostics, collision-refinement summary and source/archive hashes. Feature ablation: `artifacts/experiment-004-features/`, with all validation scores, metrics, family/zero-score support, selection, graph and provenance. Outputs are immutable; no source model is replaced and no replacement fitted bundle is required for this research comparison.

Tests must verify original positional joins/cp1252 labels, archive/source hashes, zero denominators, invalid-feature failure without cohort dropping, test-member/test-row exclusion, fixed IDs/order/settings, baseline reproduction, 27-vs-39 matrix widths, validation-only access, source immutability, score/metric parity, joint FPR/tie/nonregression rules and atomic failure handling. Selection and all reports must state remaining original timing uncertainty, sparse FTP/SSH-only training, temporal dependence and lack of independent test evidence.

## Observed results

Completed on 2 November 2026 after the design above was frozen. All extra values passed finite/nonnegative/range checks. Extraction preserved 14,342 original and 11,876 corrected retained training/validation rows. There were no invalid retained or diagnostic rows.

| Release | Features | Validation TP / attacks | Validation recall | FP / benign | Observed FPR |
| --- | ---: | ---: | ---: | ---: | ---: |
| Original | 27 | 26 / 2,021 | 1.2865% | 38 / 3,916 | 0.9704% |
| Original | 39 | 30 / 2,021 | 1.4844% | 29 / 3,916 | 0.7406% |
| Corrected | 27 | 62 / 1,725 | 3.5942% | 23 / 3,240 | 0.7099% |
| Corrected | 39 | 7 / 1,725 | 0.4058% | 22 / 3,240 | 0.6790% |

The joint rule retains **baseline27**. Expanded mean validation recall fell from 2.4403% to 0.9451%, and corrected recall regressed. All four fits succeeded and met the observed FPR ceiling. A small original-only gain does not qualify the expanded candidate for advancement. This comparison cannot attribute the effect to individual extra fields because the twelve-column block and dimension-dependent square-root subsampling act together.

The eight independent raw IAT measurements split zero existing eligible training/validation feature groups. Original binary-conflicting groups remain 49, covering 931 eligible rows, with minority-label bound 275; corrected has zero such groups on this restricted diagnostic population. These counts differ from Experiment 003's full-capture diagnostic scope. The four derived features also split zero groups, as their deterministic definitions require. No collision or duplicate-policy issue was resolved by this block.

After selection, independent verification reproduced all 10,902 baseline validation prediction rows, thresholds and metrics exactly against Experiment 003's balanced-subsample candidate. Ten source-file hashes match prior provenance; test-containing files were checked only as opaque bytes. Evidence: `artifacts/experiment-004-verification.json` and its verification script `artifacts/verify-experiment-004.py`. The full suite passes **145 tests**, including 26 feature-extraction/ablation cases. The comparison chart was visually checked for labels, intervals and captions.

No new test predictions were generated, no source model bundle was replaced and no cohorts or duplicate dispositions changed. These low validation recalls remain a failure for broad unseen-attack detection. The next model experiment should address scarce training attack support under separately declared cohort controls, rather than treating this unsuccessful block as an accuracy improvement. A richer feature block would require a new hypothesis and fixed design.
