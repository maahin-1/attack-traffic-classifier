# Experiment 009: development, freeze and evaluation plan

This is an initial design, not a frozen experiment protocol. No dataset has been assigned as the final holdout and no new model, threshold or assessment score has been created. [TON_IoT feasibility](EXPERIMENT-009-TON-IOT-FEASIBILITY.md) must pass before choosing exact captures.

## Data roles and safeguards

- **Development:** choose diverse, accessible benign and attack capture sessions with verified labels; inventory class and session support before selecting blocks. Use capture- or session-grouped development folds. If the same dataset contributes multiple roles, define non-overlapping units and disclose dependence.
- **Calibration:** reserve separate capture units containing both benign and attack support. Select the decision threshold here only, at the declared benign false-positive constraint; do not assume the final holdout shares calibration prevalence.
- **Final assessment:** reserve distinct capture units, tentatively from TON_IoT, by identifier before any candidate comparison. Never use its labels, predictions, metrics, or feature distributions for model or threshold selection. Metadata-only access needed to identify files and establish labeling feasibility must be recorded. If the holdout affects a decision after scoring, it is consumed and a new one is required for a fresh final claim.
- Pin one compatible packet-to-flow extraction contract for all raw-PCAP-derived inputs. Freeze flows, duplicates and overlapping-session treatment; use only development/calibration data for fitting. Exact feature equality is a collision indicator, not proof that distinct records are identical flows. Keep the disputed flag block excluded pending validated semantics.

## Candidate comparison

Compare the existing 27-feature random forest, a small explicitly enumerated weighted/random-forest grid, and one additional tree-based candidate only after verifying its dependencies and resource requirements. Define the exact algorithms, candidate order, resource limits, development folds and selection rule in a later locked protocol before running. Fit transformations on each training fold only. Do not use identifiers, timestamps, labels or attack-event markers as features. Report unsupported attack families rather than imputing zero support.

On the calibration block, select a threshold under a proposed observed benign FPR <=1%; ties and infeasibility must be specified before fitting. Also report uncertainty where support permits. A 1% observed FPR is not a guarantee of future FPR, especially for correlated flows. Fix the selected model, training artifacts, feature ordering, thresholds, label mapping and evaluation runner before final assessment.

## Required final reporting

Report row-weighted confusion counts, recall, precision, FPR, PR-AUC, F1 and accuracy, plus attack-family support and recall, per-capture-block results, and feature-group sensitivity where feasible. Clearly distinguish model score from a calibrated probability. Report absent classes as unsupported, not zero recall. Describe source label uncertainty, exclusions, temporal/group overlap and all predeclared failure or infeasibility cases. Use block-level uncertainty only when sufficient genuinely independent blocks exist; a row-level interval alone does not solve correlation. Any alert-volume extrapolation must identify its assumptions.

Existing captures and prior results are exploratory; no previous assessment will be represented as an untouched final test. The baseline and any candidate remain research models, not deployable detectors.
