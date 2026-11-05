# Feature block 004: directional timing and derived traffic proportions

Fixed before candidate fitting on 2 November 2026. Compare the existing ordered 27-feature policy with **39 features**: those same 27 followed by the eight raw statistics and four derived quantities below. Training and validation rows, labels, ordering and existing duplicate dispositions remain frozen. This is a validation development experiment, not a new test evaluation or a label-only correction-effect study.

## Eight raw measurements

| Original and corrected header, after whitespace trimming | Canonical name | Unit |
| --- | --- | --- |
| Fwd IAT Mean | fwd_iat_mean | microseconds |
| Fwd IAT Std | fwd_iat_std | microseconds |
| Fwd IAT Max | fwd_iat_max | microseconds |
| Fwd IAT Min | fwd_iat_min | microseconds |
| Bwd IAT Mean | bwd_iat_mean | microseconds |
| Bwd IAT Std | bwd_iat_std | microseconds |
| Bwd IAT Max | bwd_iat_max | microseconds |
| Bwd IAT Min | bwd_iat_min | microseconds |

Primary implementation evidence: [publisher-linked BasicFlow.java](https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java) and [correction maintainer BasicFlow.java](https://raw.githubusercontent.com/GintsEngelen/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java). Both compute directional inter-arrival gaps from successive packet timestamps and expose mean, standard deviation, maximum and minimum. Their rate conversions establish a microsecond time base. Getter implementations return zero when a direction has insufficient packets; zero must not automatically be read as a measured zero-length gap. CSV extraction/validation records the actual finite values rather than silently imputing missing fields.

The source-level definitions support a common alias/unit policy. They do not establish numerical equality between reconstructed flows, exact producer-commit identity, or correct ground-truth labels. The [correction documentation](https://intrusion-detection.distrinet-research.be/WTMC2021/tools_datasets.html) describes changed flow termination and regenerated populations. Directional timing statistics can consequently change substantially even when corresponding field definitions agree.

Hypothesis: per-direction gap distributions add information beyond total directional gaps and whole-flow IAT statistics already in the 27 features. This may help distinguish traffic patterns with similar aggregate totals; it supplies no examples of attack families absent from training and makes no performance promise.

## Four derived quantities

Let `F/B` be forward/backward packet counts and `X/Y` the corresponding payload-byte totals from the existing policy.

| Canonical feature | Formula | Unit |
| --- | --- | --- |
| fwd_packet_fraction | F / (F + B) | dimensionless |
| fwd_byte_fraction | X / (X + Y) | dimensionless |
| fwd_bytes_per_packet | X / F | bytes per packet |
| bwd_bytes_per_packet | Y / B | bytes per packet |

For every formula, a zero denominator returns exactly `0.0`. This is a declared convention, not evidence that an undefined physical ratio equals zero. No labels, timestamps, endpoint addresses, ports, attempted categories or source IDs enter these calculations. The derived columns are deterministic functions of existing numeric inputs, so they **cannot separate rows already identical across all 27 base features**. They may make useful relationships easier for axis-aligned, depth-bounded trees to express.

## Extraction and experiment controls

The extraction artifact joins existing retained train/validation rows and later duplicate diagnostic rows to their pinned archive/member/source-record references. It validates raw source labels and the original 27-feature projection hash before reading added measurements into the experiment. No test rows are extracted or interpreted. Raw identities remain local references and are not model inputs.

Any missing, duplicate, nonnumeric, nonfinite or negative added gap value in a retained training/validation row blocks the expanded experiment. The four derived inputs (directional counts and byte totals) must also be finite and nonnegative, derived fractions lie in [0,1], and bytes-per-packet outputs are nonnegative. These are the pre-extraction Experiment 004 validity rules: a source negative gap is exposed as a data-quality failure, not silently removed or changed to zero. Do not drop that row, fit only the surviving release, or impute silently: each would change the preregistered comparison. Invalid added values on already quarantined diagnostic rows can limit collision-refinement diagnostics but do not justify changing their frozen dispositions.

Eight raw measurements may distinguish some previously identical 27-feature projections. That is a descriptive diagnostic, not permission to restore quarantined rows. Both candidates use the original retained cohort and duplicate policy; otherwise feature gains would be confounded with population changes.

Both candidates use the same random forest settings: 200 trees, depth 12, minimum leaf size 2, seed 42, one worker and `class_weight='balanced_subsample'`, with identity preprocessing. Retain explicit `max_features='sqrt'`: it considers effectively five columns per split at 27 inputs and six at 39. This dimension-dependent behavior is part of the standard fixed policy, not a separately tuned parameter. The baseline therefore reproduces Experiment 003's selected candidate. [RandomForestClassifier documentation](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html)

Threshold selection and candidate selection use validation only. Compare both releases under each candidate, publish every outcome, and apply the preregistered joint mean-recall/FPR and no-variant-regression rule. No prior test-result file or serialized model is needed. Remaining source-padding, ambiguous original clock, sample selection, label conflict, correlated-flow uncertainty and already-examined-capture limitations persist.
