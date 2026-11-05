# Experiment 007: assessment error analysis

## Scope and evidence

The protected 2018-11-03 CIC-DDoS2019 assessment contains 20,364,525 valid rows: 20,307,560 attack and 56,965 benign. The four models, their Experiment 006 thresholds, and the newly calibrated thresholds were frozen before assessment. The primary analysis retains all valid rows, including repeated feature vectors. This is an analysis of a single lab capture, not independent evidence of deployment performance.

Sources: `artifacts/experiment-007-assessment/report.json` (SHA-256 `7493f3a16515a16058cf92ed1b0846ae4704a069389e4a786591dcfcfae64902`), `artifacts/experiment-007-quality-audit/report.json` (SHA-256 `03abf876a19cb3313c8f6f93b41b8b6e74d9f0f78122f762915a58666d7b6639`), and the audit's `groups.sqlite`. The overlap figures below sum the stored calibration-benign, calibration-attack, assessment-benign, and assessment-attack counts per 27-feature digest; they do not use model scores.

## Threshold transfer

| Model | Threshold source | Attack recall | Benign FPR | TP | FP |
| --- | --- | ---: | ---: | ---: | ---: |
| Original reference | Experiment 006 | 50.718% | 0.964% | 10,299,492 | 549 |
| Original reference | Experiment 007 calibration | 50.721% | 1.648% | 10,300,102 | 939 |
| Original candidate | Experiment 007 calibration | 0.0012% | 0.499% | 243 | 284 |
| Corrected reference | Experiment 007 calibration | 0.729% | 0.987% | 148,100 | 562 |
| Corrected candidate | Experiment 007 calibration | 18.848% | 17.516% | 3,827,535 | 9,978 |
| Corrected candidate | Experiment 006 | 74.983% | 37.274% | 15,227,126 | 21,233 |

For the original reference, the new calibration threshold detected 610 more attack rows than the prior threshold, while adding 390 benign false positives. Its observed FPR exceeded the 1% target. The prior threshold met that target on the assessment (549 / 56,965 benign rows), but its nominal 95% Wilson interval is approximately 0.887%–1.047%, assuming independent rows. Dependence from repeated patterns makes that interval insufficient as a deployment guarantee.

The corrected candidate illustrates the recall/FPR tradeoff on this capture: its previous threshold caught 74.983% of attacks at 37.274% FPR; the recalibrated threshold caught 18.848% at 17.516% FPR. Neither met the 1% target. Scores alone do not identify why the model makes these errors.

## Attack families missed by the original reference

These rows use its previously frozen Experiment 006 threshold (0.0383333333), which met the observed assessment FPR target. Percentages are row-weighted recalls, not recalls over independent events.

| Family | Assessment rows | Detected | Recall |
| --- | ---: | ---: | ---: |
| LDAP | 1,915,122 | 1,597,418 | 83.411% |
| MSSQL | 5,787,453 | 4,471,598 | 77.264% |
| NetBIOS | 3,657,497 | 2,654,073 | 72.565% |
| PortMap | 186,960 | 150,468 | 80.481% |
| SYN | 4,891,500 | 2,585 | 0.053% |
| UDP | 3,867,155 | 1,423,294 | 36.805% |
| UDP-Lag | 1,873 | 56 | 2.990% |

The aggregate 50.718% recall conceals especially poor SYN and UDP-Lag detection. The corrected candidate's recalibrated threshold caught 78.237% of SYN rows, but its 17.516% benign FPR failed the operating constraint. This is a candidate tradeoff to investigate on development data, not a deployable result.

## Repeated features and label conflicts

The audit identified 7,171,162 distinct 27-feature groups among 70,427,637 rows; 63,256,475 rows occur after the first occurrence of their group. Of 152,915 groups present on both capture days, their members account for 35,279,015 calibration rows (70.469%) and 16,466,245 assessment rows (80.857%). Feature equality does not establish that two rows represent the same network flow.

There are 669 groups containing both benign and attack labels across the combined captures. They contain 1,699,645 calibration rows and 2,742,508 assessment rows (13.467% of assessment rows). Within the assessment day alone, 96 groups contain both binary labels and account for 2,741,182 assessment rows. These are identical model inputs with inconsistent binary labels; no deterministic classifier using only these 27 features can assign different predictions within such a group. The figures do not by themselves establish which labels are wrong.

Assessment traffic is 99.720% attack rows. Consequently, precision calculated from this capture can look very high and should not be extrapolated to a network with a different attack prevalence. Raw row counts and ordinary row-level confidence intervals also overstate independent evidence when flows share feature vectors or capture conditions.

## Recommended next experiment

1. Investigate representative conflicting groups against timestamps, source labels, and original capture documentation. The group-label-weighted and conflict-excluded descriptive analyses are complete; see `docs/EXPERIMENT-007-SENSITIVITY-RESULTS.md`. Retain the original row-weighted outcome alongside them.
2. Use separate development data to investigate SYN/UDP-Lag failures, feature semantics, and alternative models or training coverage. Do not tune on the consumed 2018-11-03 assessment results.
3. Before claiming improvement, freeze the new model and operating threshold, then evaluate once on a new, independently sourced capture with benign support and attack-family coverage. Report per-family recall, benign FPR, and group/temporal dependence alongside row-weighted metrics. Choosing a winner after observing the current assessment would make this capture development evidence for that choice.
