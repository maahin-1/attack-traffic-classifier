# Post-evaluation distribution and error audit

This diagnostic uses the already examined 2018 days and the unchanged frozen models. It is descriptive development evidence, not another held-out test. No model was fitted and no threshold changed. `artifacts/ids2018-shift-audit/diagnostic.json` contains all 27-feature summaries, training-range comparisons, false-positive/true-negative summaries, zero-score counts, descriptive feature importances and input hashes. `attack_traffic/shift_audit.py` reproduces it into a new destination. Two focused synthetic summary tests pass.

## Findings

The most striking benign shift is on 16 February. Forward packet-length standard deviation is zero in 64.21% of original training benign flows and 62.51% of corrected training benign flows, versus only 0.98% of 16 February benign flows. Backward packet-length standard deviation similarly changes from 70.48% / 63.30% zero to 0.99% zero. Forward/backward minimum packet lengths are zero in 100% of that day's benign flows, versus 43.03% / 45.50% in original training and 38.17% / 38.76% in corrected training. Thus a dramatic distribution shift exists even when measurements remain inside training min/max ranges. It cannot be attributed uniquely to traffic, extractor differences, labels or source-file coverage from this evidence.

Only 2.40% of 15 February benign flows have flow-IAT mean outside the corrected model's benign training range; 2.29% have duration outside that range. Broad training min/max coverage therefore does not establish distributional stability or explain all errors. No saturation threshold is invented: maxima and approximate p99 values are reported for further inspection. Required-feature invalid/missing rows were already accounted for in the frozen evaluation's quality report (only one repeated header was excluded across these two days); the diagnostic consumes exactly its eligible-row policy.

False-positive profiles also differ by model on 15 February:

| Frozen model | Approximate FP median duration | Approximate TN median duration | Exact FP fraction with no backward packets |
| --- | ---: | ---: | ---: |
| Original-trained | 36 microseconds | 37,302 microseconds | 22.7% |
| Corrected-trained | 54,518,135 microseconds | 6,757 microseconds | 75.1% |

For original-trained false positives on that day, 88.6% have zero forward packet-length standard deviation and 97.4% have zero forward minimum length, versus 59.0% and 62.5% of true negatives. The corrected model instead frequently flags long, one-directional benign-labeled flows. These differences are correlations within already observed errors; they are not proof that a single feature causes the failure or that changing it would improve detection.

On 16 February, 601,788 of 601,802 attack-labeled rows score exactly zero under the corrected model. This accounts for all its false negatives at the fixed positive threshold. The original model has 459,908 attack rows scoring zero. Lowering thresholds cannot safely distinguish tied zero-score attacks from zero-score benign traffic; that day also has 446,030 corrected-model and 435,762 original-model benign rows at zero. This pattern motivates studying missing training-family support and dataset/extractor coverage rather than claiming that a threshold tweak solves the problem.

Impurity importances describe the fitted training forests only. The original forest's largest weight is forward packet-length standard deviation (0.143); the corrected forest's largest weights are backward packet count (0.142), backward IAT total (0.122) and duration (0.119). These are biased, noncausal training statistics, not external feature-attribution explanations.

## Verification and limits

Rescoring reproduces every prior daily TP/FP/TN/FN and zero-score total exactly for both models. Across 2,097,149 eligible rows per model, no score or threshold policy changed. Input files, source files and model hashes are checked before and after the audit. It does not compare or inspect the old 2017 test partition.

Counts, extrema and zero/negative and outside-training-range fractions use the full population; arithmetic fractions and means are subject to floating-point rounding. An absent external class has null range-violation and zero-fraction-difference estimates. Quantiles use a deterministic uniform random-priority reservoir capped at 4,096 rows per group (NumPy seed 42); their values have sampling error and are not exact population medians. Reservoirs are distinct per group; comparisons also confound attack-family composition. Units and column meanings retain the cross-version uncertainty documented in the robustness protocol. Labels remain supplied labels rather than adjudicated ground truth. Three synthetic tests establish bounded deterministic sampling, hand-computed moments/counts, invalid-input rejection and null fractions for absent classes; exact full-data score-accounting parity supplies the additional integration check.

The next experiment should first resolve coverage/extractor questions, then explicitly introduce representative attack-family training support using a separate development capture and a future assessment block. The current two days can inform that design but cannot validate its eventual model. Preserve these frozen outcomes as evidence of the present model's limited transfer.
