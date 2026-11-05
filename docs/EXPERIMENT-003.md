# Experiment 003: duplicate diagnostics and validation-only class-weight ablation

Design recorded on 2 November 2026 before fitting any Experiment 003 candidate. This experiment implements the improvement review's first recommendation. It is development research on an already examined capture, not an independent generalization or deployment test.

## Frozen evidence and scope

Source run: `artifacts/paired-capture-date/` (Experiment 002). The existing data-release comparison, raw/prepared files, feature policy, retained row IDs, ordering, capture-day partitions, duplicate policy, labels and thresholds remain unchanged. This experiment creates new immutable outputs; it does not replace or edit the source benchmark.

Part A audits all saved feature-equivalence groups, including later quarantined copies, without changing any disposition. It distinguishes raw-label conflicts, binary-label conflicts, groups spanning dates, and source-class losses. Boundary quarantines remain separate from duplicate groups. Matching 27 numeric feature values is not proof of identical flow identity. Group minority-label counts are a descriptive ambiguity bound before quarantine, not an adjudication of ground truth. The diagnostic audit may describe all partitions, but it cannot alter the candidate list, fitting data or selection rule below.

Part B uses **only the original frozen training and validation rows**. Test rows are discarded before parsing their labels/features. The ablation never opens the source `metrics.json` or `predictions.csv`, never computes test scores and never selects from test outcomes. Existing Thursday–Friday results remain exploratory and frozen; a subsequent assessment on that capture would not constitute a new untouched holdout.

Training supports: original 8,306 benign / 99 attacks; corrected 6,837 benign / 74 attacks. Training attacks are FTP/SSH only. Validation supports: original 3,916 benign / 2,021 attacks; corrected 3,240 benign / 1,725 attacks. Validation attacks are unseen DoS families. Class weighting cannot create examples of absent families.

## Candidate and threshold contract

The three fixed candidate settings, in tie-preference order, are:

1. `unweighted`: `class_weight=None`.
2. `balanced`: training-frequency inverse class weights.
3. `balanced_subsample`: training-bootstrap inverse class weights per tree.

All other settings remain the source's 200 trees, depth 12, minimum leaf size 2, seed 42, one worker and 27 numeric features. No class balancing/resampling of validation is allowed. Each candidate uses the **same class-weight setting on both releases**. No depth/leaf/feature grid, new features, enlarged training population, dedup change or family-model change is included in this ablation.

Each candidate/variant selects a validation-only threshold using the existing highest-recall rule under observed benign FPR <=1%, breaking threshold ties by fewer alerts and then higher threshold. An all-negative point remains possible and must retain its no-useful-detection disclosure. This is an empirical FPR target; confidence bounds and future-network performance are not guaranteed.

## Joint selection and conservative advancement

A candidate is jointly eligible only when both release evaluations succeed and both validation FPRs satisfy the 1% ceiling. Rank eligible candidates by:

1. Higher unweighted mean of the two validation attack recalls.
2. Lower mean validation FPR.
3. Earlier candidate order, favoring `unweighted` on a complete tie.

Publish the joint winner separately from an advancement recommendation. A weighted candidate advances only if its mean validation recall strictly exceeds the unweighted reference (numeric comparison tolerance 1e-12), neither variant's validation recall regresses (same tolerance), and both FPR constraints hold. Otherwise retain the unweighted baseline. Candidate failures remain visible; they must not become successful zero-score predictions or silently change the grid. If the reference fails validation/reproduction, do not claim an improvement over it.

## Evidence and acceptance

Export every candidate/variant's validation threshold, confusion counts, FPR, attack recall, precision, average precision, precision@100, family support/recall, zero-score overlap and Wilson intervals. Record training support, wall time, source/config/cohort hashes, chosen candidate and advancement rationale. No test results belong in these artifacts. The unweighted validation scores/metrics must reproduce the frozen reference when checked separately after selection.

Tests must cover exact data/setting controls, train-only fitting, absence of test evaluation, invariance to changed test rows/scores, deterministic selection/tie rules, FPR failure, per-variant regression rejection, malformed/missing inputs, row caps, source immutability and atomic publication. Duplicate-audit tests must verify group-vs-row counts, minority ambiguity bounds, class losses and source consistency.

Output directories: `artifacts/experiment-003-duplicate-audit/` and `artifacts/experiment-003-class-weights/`. Neither output is published until complete. A validation gain is a hypothesis for later independent evaluation; it does not establish better test accuracy or operational usefulness.

## Observed duplicate audit

The audit verified source row IDs, quality totals, retained feature digests and existing representative-conflict counters. Eligible feature groups include retained representatives and later duplicate copies; two original numeric exclusions and fourteen original boundary quarantines remain separate.

| Diagnostic | Original | Corrected |
| --- | ---: | ---: |
| Eligible selected records | 28,218 | 20,909 |
| Feature groups | 22,964 | 18,866 |
| Groups containing repeated feature vectors | 862 | 215 |
| Binary-conflicting groups | 86 | 8 |
| Eligible records in binary-conflicting groups | 1,418 | 159 |
| Minority-label disagreement bound before quarantine | 391 | 10 |
| Later copies conflicting with the retained binary label | 676 | 137 |

Original Portscan loses 1,339/1,545 sampled rows (86.67%); corrected Portscan loses 1,505/1,600 (94.06%), and corrected infiltration-portscan loses 433/701 (61.77%). This changes the target population toward unique feature patterns. Group equality does not establish source-flow identity, and conflicts cannot be resolved by deterministic transformations of the same vector alone.

The minority-label bound describes disagreement with the supplied labels on pre-quarantine feature groups. It is not an error floor for the retained evaluation cohort or proof of incorrect labels. Quarantined feature assignments use saved group hashes; only retained numeric vectors were independently rehashed. This is a saved-artifact diagnostic, not a fresh identity audit of every raw flow. No rows were relabeled, restored, removed or reassigned.

## Observed validation ablation

All six candidate/release fits succeeded. Same-source unweighted thresholds, metrics and **10,902 validation predictions** exactly reproduced the frozen reference in a separate post-selection verification. Benchmark source hashes remained unchanged.

| Candidate | Original recall | Original FPR | Corrected recall | Corrected FPR | Mean recall |
| --- | ---: | ---: | ---: | ---: | ---: |
| Unweighted | 1.286% | 0.945% | 2.551% | 0.926% | 1.919% |
| Balanced | 1.286% | 0.664% | 0.522% | 0.679% | 0.904% |
| Balanced subsample | 1.286% | 0.970% | 3.594% | 0.710% | 2.440% |

The fixed joint rule selects **balanced_subsample** for advancement to further research: mean validation recall improves by **0.5217 percentage points**, neither variant's recall regresses and both observed FPR ceilings hold. Original true positives remain 26; its false positives increase from 37 to 38. Corrected true positives increase from 44 to 62, while false positives fall from 30 to 23. Corrected validation precision@100 increases from 52% to 64%. Plain balanced weighting performs worse on corrected validation and is not advanced.

The result remains weak: 1,964/2,021 original validation attacks (97.18%) and 1,663/1,725 corrected attacks (96.41%) receive score zero under the selected candidate. Corrected average precision changes only from 0.35819 to 0.35907. The observed operating-point gain does not demonstrate broad unseen-family separation, statistical significance or future-network performance. Flow-level confidence intervals overlap and do not model temporal dependence or repeated selection.

No new test predictions or test metrics were computed. Selection never used source test outcomes or collision diagnostics. No fitted-model bundle was persisted or installed into the source run: `promoted_candidate` is an experimental advancement recommendation, not deployment or replacement of the frozen models. Further candidate assessment remains development research on inspected captures until genuinely independent evaluation data are available.

Artifacts: `artifacts/experiment-003-class-weights/report.md`, `candidate_metrics.csv`, `candidate_metrics.json`, `validation_predictions.csv`, `per_class_validation.csv`, `selection.json`, `validation_recall.png` and `provenance.json`. Duplicate diagnostics live in `artifacts/experiment-003-duplicate-audit/`. Independent baseline verification is `artifacts/experiment-003-verification.json`. The full suite passed **119 tests**, including test-row mutation invariance, forbidden test-result access, exact reproduction and source immutability.

## Reproduction

```powershell
python main.py audit-collisions --run artifacts/paired-capture-date --output artifacts/experiment-003-duplicate-audit
python main.py tune-weights --run artifacts/paired-capture-date --output artifacts/experiment-003-class-weights --chart
```

Choose new output directories when rerunning; published evidence cannot be overwritten. The next data experiment should investigate projection collisions and additional independent measurements with a documented common cohort, rather than simply removing duplicate protection or chasing the current test score.
