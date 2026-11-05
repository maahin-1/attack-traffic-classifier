# Experiment 005: increased training support

Design recorded before any model fitting. The question is whether more pre-validation traffic improves validation attack recall under the existing observed 1% false-positive-rate ceiling. This is exploratory research on the existing capture, not independent test evidence.

Keep the 27-feature balanced-subsample reference and its forest settings, frozen validation IDs/order/labels and threshold-selection policy from Experiment 004. Preserve the current retained training rows and duplicate decisions. Compare that baseline with a candidate adding a deterministic label-independent nested 10% sample of pre-validation source records (`subset-v1` hash modulo 10 equals zero, excluding the existing modulo 100 sample). Include both benign and attack rows; report their support and class mix. No new validation or test labels are used to select added training rows. Only the same early capture days are eligible, so extra data does not add later attack families.

Check each supplemental record against the same source schema, label map, finite feature, capture-date and boundary controls used in the baseline. Retain the existing representatives, deduplicate additions deterministically against them and one another, and exclude added feature groups matching frozen validation or test groups without consulting test labels or scores. The test-group check is a disclosed transductive leakage guard based on feature-group identities, not an independent prospective evaluation. Record all exclusions and exact cohort hashes; reject ambiguous identities or unverifiable source provenance. Original AM/PM and timezone remain unresolved.

Evaluate baseline and expanded training on the same validation populations. Each uses a validation-selected threshold at observed FPR <=1%; rank by mean original/corrected recall, then mean FPR, then baseline. Advance only if mean recall improves and neither release regresses by more than 1e-12. Compare class support and per-family outcomes, and retain all candidate results even if the hypothesis fails. No new test scoring, duplicate-policy replacement or model deployment. Outputs use fresh immutable locations. Baseline validation predictions must reproduce Experiment 003 exactly, and tests must establish sample nesting, exclusion accounting, frozen cohorts, deterministic deduplication and holdout isolation.

## Results

The nested sample added 879 attacks and 69,780 benign records for original data, and 607 attacks and 60,291 benign records for corrected data. It excluded 17,151 original and 1,452 corrected records matching frozen or earlier supplemental feature groups, plus 98 original boundary cases and two invalid original records. The guard excludes all recorded frozen groups, including quarantined groups. The full exclusion ledger and hashes are in `artifacts/experiment-005-training-support/`.

| Variant | Training sample | Attack recall | Observed FPR | Training attacks |
| --- | --- | ---: | ---: | ---: |
| Original | Baseline | 1.29% | 0.970% | 99 |
| Original | Expanded | 3.81% | 0.996% | 978 |
| Corrected | Baseline | 3.59% | 0.710% | 74 |
| Corrected | Expanded | 0.75% | 0.525% | 681 |

The rule retains the baseline: the corrected variant regressed, and mean validation recall also declined. All observed FPRs are under the ceiling. The intervention changes overall training sample size and class mix as well as attack support; the result does not isolate a causal effect of attack count. Added early examples do not introduce later attack families.

Independent review confirmed all 10,902 baseline validation predictions, thresholds and metrics match Experiment 003 exactly. The complete test suite passed 154 tests. Detailed scores, class breakdown, selection and provenance are in `artifacts/experiment-005-ablation/`. No new test scores or replacement model bundles were produced. Repeated use of this validation capture increases selection bias; further progress needs a new independent evaluation capture or a separately designed temporal evaluation, not a claim of improved real-world accuracy.
