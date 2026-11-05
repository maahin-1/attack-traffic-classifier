# Experiment 008: corrected 2017 development comparison

This comparison explores feature choices in the corrected CICIDS2017 release only. The source sample, 27-feature source joins, label mapping, and per-row protocol/flag values were checked against the fingerprinted corrected archive. The experiment does not load the CIC-DDoS2019 assessment or train on the original 2017 release. The same Wednesday development rows select each threshold and report its metrics; these results are optimistic and cannot establish independent improvement or generalization.

All four arms use identical rows and the same groups defined by the original 27 features. A group is retained at most once in training; Wednesday excludes any group already present in training and retains the first Wednesday representative of remaining groups. Monday–Tuesday training contains 6,837 benign and 74 attack rows. Wednesday development contains 3,240 benign and 1,725 attack rows. The source-specific corrected flag counts are not assumed equivalent to the original-release or CIC-DDoS2019 flags.

| Feature set | Threshold selected on Wednesday | Wednesday attack recall | Wednesday benign FPR | TP / FP |
| --- | ---: | ---: | ---: | ---: |
| Existing 27 | 0.00750 | 2.55% | 0.93% | 44 / 30 |
| 27 + protocol | 0.00667 | 3.65% | 0.80% | 63 / 26 |
| 27 + seven flag counts | 0.01000 | 3.36% | 0.80% | 58 / 26 |
| 27 + protocol and flags | 0.00900 | 2.43% | 0.74% | 42 / 24 |

Each threshold maximizes recall on Wednesday under an observed 1% FPR limit, with tied scores handled together. All four arms detect zero attacks at the fixed 0.5 threshold on the same Wednesday rows. The protocol arm's 19 additional true positives over baseline are mostly associated with Slowloris: 27 of 34 rows detected versus 10 of 34 for baseline. All four arms miss all 66 GoldenEye attack rows. These class supports are small and the attack mix does not contain a labeled SYN flood. The comparison does not establish improved SYN detection, nor does it justify choosing a deployment model.

The original 2017 published flag counts and corrected-release flag counts have different known extraction behavior. CIC-DDoS2019 producer-version compatibility is unresolved; see `docs/EXPERIMENT-008-FEATURE-FEASIBILITY.md`. Protocol can encode capture-specific regularities and is not automatically safe from shortcut learning. No 2019 assessment score was produced in this run.

The executable is `scripts/experiment008_dev_compare.py`; `tests/test_experiment008_dev_compare.py` contains two focused checks. The pre-scoring protocol is `artifacts/experiment-008-dev-comparison/protocol.json` (SHA-256 `5a585e2303272dfaa01a313019d84ce24bb57ec94952e7e2773f982bfe56990a`). The result is `artifacts/experiment-008-dev-comparison/report.json` (SHA-256 `233a3624afce743b275662a40906dbd2728394a9e0ad1df160b30fb2c5ce7a41`). An independent code review found no substantive shared-cohort or split issue; it noted that the acquisition metadata and Experiment 006 manifest consulted to authenticate inputs were not fingerprinted in the pre-run protocol. Their hashes were recorded **after** the run in `provenance-supplement.json`; that does not establish their pre-run state. These local hashes record integrity but are not an independently timestamped preregistration.
