# Experiment 007: descriptive sensitivity results

The analysis followed `docs/EXPERIMENT-007-SENSITIVITY-PLAN.md`, which was recorded after the original assessment was consumed and before this sensitivity run. It reused the frozen four models and both existing threshold sets; no model or threshold was selected or changed. The results describe the same assessment capture and are not independent confirmation.

All 20,364,525 assessment rows were processed without feature errors. The run reconstructed the original row-weighted TP, FP, TN, and FN exactly for all eight model/threshold combinations. It found 1,599,709 assessment `(feature group, binary label)` pairs: 1,559,997 attack and 39,712 benign. Excluding groups with both binary labels anywhere across the two captures removed 2,742,508 assessment rows, leaving 17,571,007 attack and 51,010 benign rows.

Each cell below is **attack recall / benign FPR**, in percent. Group-label weighting gives equal weight to each distinct 27-feature digest and binary label present in the assessment; a conflicting group can contribute one unit to each class. Conflict-excluded results retain row weights for remaining groups. Neither view measures independent flows.

| Model and threshold | Original row-weighted | Group-label weighted | Conflict-excluded rows |
| --- | ---: | ---: | ---: |
| Original reference, Experiment 006 | 50.718 / 0.964 | 0.276 / 0.959 | 58.616 / 0.908 |
| Original reference, recalibrated | 50.721 / 1.648 | 0.284 / 1.325 | 58.620 / 1.627 |
| Original candidate, Experiment 006 | <0.001 / 0.154 | <0.001 / 0.068 | <0.001 / 0.049 |
| Original candidate, recalibrated | 0.001 / 0.499 | 0.014 / 0.415 | 0.001 / 0.353 |
| Corrected reference, Experiment 006 | 1.567 / 3.722 | 18.010 / 4.492 | 1.811 / 4.156 |
| Corrected reference, recalibrated | 0.729 / 0.987 | 9.272 / 1.320 | 0.843 / 1.102 |
| Corrected candidate, Experiment 006 | 74.983 / 37.274 | 34.126 / 17.944 | 71.087 / 30.408 |
| Corrected candidate, recalibrated | 18.848 / 17.516 | 13.303 / 7.620 | 6.214 / 12.862 |

The original reference at its Experiment 006 threshold illustrates why weighting matters: 50.718% row-weighted recall becomes 0.276% under equal group-label weighting, while conflict exclusion raises row-weighted recall to 58.616%. These are different estimands: repeated patterns receive high weight in the first and third views, while every observed feature-group/class pair gets equal weight in the second. Neither result establishes which weighting matches real traffic. Excluding conflicts may introduce selection bias and does not prove the remaining labels correct.

The original reference's observed FPR remains below 1% in these three views, but its group-label-weighted recall is extremely low. The corrected reference's recalibrated threshold meets the observed 1% FPR limit only in the original row-weighted view. The corrected candidate misses the FPR limit under all three views. This comparison does not establish performance on other captures or justify tuning on this consumed assessment.

Artifacts: `artifacts/experiment-007-sensitivity/report.json` (SHA-256 `2d36c527ecc7cc352858eb5687119975007582f38c42aadaefd05fdfc3d69856`), `protocol.json` with the pinned model, threshold, audit, adapter, plan and runner hashes, and `dependency-hashes-during-run.json` for imported helpers. Those helper hashes were recorded during execution and matched after the run; they are not a pre-run freeze. The original assessment and audit remain unchanged.

The high-volume and conflicting-group trace is complete; see `docs/EXPERIMENT-007-GROUP-INVESTIGATION.md`. Develop changes only on separate development data, and reserve a new independent capture for final evaluation.
