# Implementation roadmap

Source of truth: [PRD 01](../PRD-01-attack-traffic-classifier.md) and [TRD 01](../TRD-01-attack-traffic-classifier.md). See [requirements review](REQUIREMENTS-REVIEW.md) for unresolved real-data decisions.

## Current research checkpoint — 5 November 2026

The offline pipeline and the exploratory original/corrected comparison exist. A synthetic clean virtual-environment smoke test has passed, but the project has not passed the final release review or a fresh full-data reproduction. The dated history below is not the current experiment queue.

Experiments 006–008 extended model and data-quality research. The previously consumed CIC-DDoS2019 assessment does not serve as an independent final test. Its [sensitivity analysis](EXPERIMENT-007-SENSITIVITY-RESULTS.md) shows that results depend strongly on repeated feature groups and threshold choice. The [development feature comparison](EXPERIMENT-008-DEVELOPMENT-COMPARISON.md) is exploratory and does not establish a transferable model improvement. Packet investigations found possible discrepancies in flag columns; [current evidence](EXPERIMENT-008-STRATIFIED-FLAGS.md) does not establish a complete mapping or the cause. Continue excluding the disputed flag fields from the shared cross-release feature policy.

Remaining research release work:

1. The targeted ECE/CWR packet-to-source-flow investigation is complete: one same-tuple CSV flow begins after both rare-flag packets under the supported but not independently synchronized clock hypothesis. See [results](EXPERIMENT-008-RARE-FLAG-MATCH-RESULTS.md). Keep the existing feature policy until equivalent semantics are demonstrated.
2. The [clean virtual-environment synthetic smoke test](CLEAN-ENVIRONMENT-SMOKE-2026-11-05.md) passed fixture training, report rebuilding and saved-model scoring parity. Its limitations include two test rows per variant and unpinned transitive dependencies; an offline install and fresh full-data run were not established.
3. The [AT-P01–AT-P07 evidence review](RELEASE-REVIEW-2026-11-05.md) is complete for the Experiment 002 research subset; qualified timing, dependency and dataset-use limitations remain. README and model card now point to newer experiments. A publication package still needs a separate review.
4. For a later model-generalization claim, design changes using separate development data, freeze the model and threshold, then assess on a genuinely independent capture. The acquisition date and availability of such a capture are not established.

The initial [release evidence checkpoint](RELEASE-CHECKPOINT-2026-11-05.md) records remaining verification work. A [local source-only research package](RESEARCH-PACKAGE-REVIEW-2026-11-05.md) has been built and tested after extraction; a final third-party rights and content review remains before any external distribution. These checks are not a production certification.

The user selected the MIT license for project-authored code. The new [TON_IoT feasibility inventory](EXPERIMENT-009-TON-IOT-FEASIBILITY.md) and [development plan](EXPERIMENT-009-DEVELOPMENT-PLAN.md) start the next research track; no exact independent holdout has yet been reserved. The unauthenticated official download path redirected to sign-in, and capture inventory, extraction compatibility, label alignment and assessment selection remain open.

## Verified progress — 2 November 2026

Stages 1/2 software, both release adapters and a qualified real-data capture-day comparison are implemented. [Experiment 002](EXPERIMENT-002.md) compares independent 1% subsets under a shared 27-feature/model/date policy, with all source-padding and sampled-row losses disclosed. Saved-score reports, grouped class-comparison charts, Parquet exports and exact model-scoring parity are verified. The full suite passed 101 tests. See [model card](MODEL-CARD.md) for the principal generalization failures.

[Experiment 003](EXPERIMENT-003.md) subsequently completed a diagnostic collision audit and validation-only class-weight ablation. Balanced subsample weighting modestly improves corrected validation recall (2.55%→3.59%) without original recall regression; no test evaluation or source-model replacement occurred. Duplicate grouping/population controls remain unchanged. The current full suite passes 119 tests.

The stronger exact-UTC-instant contract remains unresolved because original AM/PM/timezone were lost. The paired result deliberately uses capture dates and conservative uncertainty bounds; it does not certify that stronger contract or establish label-only causal effects. Temporal-block comparison uncertainty is unavailable with only two test capture days. Clean-environment reproduction and a final requirement-by-requirement release review remain. The agent did not submit registration details or commit/push changes.

[Experiment 004](EXPERIMENT-004.md) tested eight directional packet-gap measurements plus four ratios on frozen cohorts. The 39-feature block failed the joint validation rule: original recall 1.29%→1.48%, corrected 3.59%→0.41%. The research reference remains 27 features with balanced subsample weighting. No existing feature-group conflicts were separated. Baseline reproduction matches all 10,902 validation rows, source hashes are unchanged, and the full suite passes **145 tests**. Next model work should assess increased training attack support as a separate cohort experiment; clean-environment release verification remains outstanding.

[Experiment 005](EXPERIMENT-005.md) increased early training support under a fixed validation comparison. The original variant improved and the corrected variant regressed; baseline retained. Repeated use of this validation capture requires a fresh independent evaluation design before claiming generalization. Full suite: 154 tests.

Post-evaluation diagnoses: [coverage](IDS2018-COVERAGE-AUDIT.md) and [shift](IDS2018-SHIFT-AUDIT.md) audits are complete. Exact copies of recorded objects do not prove complete daily captures; clock ambiguity blocks hour-based splits. Frozen confusion totals reproduce, but tied zero scores and benign shifts expose limited transfer. [Experiment 006](EXPERIMENT-006-PLAN.md) is the selected next design, with provenance and future-assessment gates before fitting; it has not been executed.

## Stage 1 — provenance, adapters and audit foundation

Implement local CSV ingestion, explicit schema/label mappings, numeric feature allowlists, file and schema hashes, row disposition accounting, time parsing, preliminary chronological partitioning and duplicate quarantine. Supply synthetic original/corrected fixture profiles and a documented audit command. Start here; no model fitting or data download is needed.

Acceptance evidence:

- Every fixture row has exactly one disposition and a documented reason; totals reconcile by variant and raw class.
- Nonfinite numeric values, malformed timestamps and invalid durations are visible.
- Identifier sentinel columns and label-derived features cannot enter the allowlist.
- Boundary-spanning rows and later duplicate groups cannot leak across partitions.
- Unknown labels, missing/ambiguous columns and invalid configuration return actionable failures.
- Run artifacts identify synthetic provenance, feature policy, split boundaries and class support; repeated runs do not overwrite prior evidence.

PRD coverage: foundation for AT-P01, AT-P02, AT-P03 and AT-P07. This stage alone does not pass the complete requirements.

## Stage 2 — real-release contract and leakage-safe baseline

Select and record exact original/corrected releases and usage terms. Inspect their real schemas, map equivalent feature semantics/units and attempted labels, inventory time/class coverage, then freeze identical boundaries and feature policy. Add pinned, tested numerical dependencies, training-only preprocessing, a constant baseline, bounded random forest and validation-only threshold selection.

Acceptance evidence:

- Both variants have verified manifests and reconciled row losses; real-data adapter tests use small permissible fixtures.
- Training and validation contain adequate binary support; later test classes retain seen/unseen status.
- Validation maximizes recall under the declared 1% FPR ceiling, applies deterministic tie rules and reports infeasibility explicitly.
- Test scores never influence tuning; saved preprocessing and model scoring agree with the training path.
- Resource measurements identify hardware, sample/full profile, wall time, peak memory and throughput.

PRD coverage: AT-P01 through AT-P04 foundations, AT-P06 metric foundations.

## Stage 3 — original/corrected experiment comparison

Run matched settings on the two independently processed populations. Export frozen-threshold predictions, confusion counts, FPR, recall, precision, PR-AUC, pooled precision@100, uncertainty intervals and detailed class support/recall. Preserve attempted-label audit slices without implying unseen family learning.

Acceptance evidence:

- Hand-computed metric fixtures cover tied scores, empty denominators and absent classes.
- Stable IDs break ranking ties; unsupported recalls are null and uncertainty limitations are visible.
- Reports distinguish population differences from controlled settings and avoid causal label-only claims.
- Temporal-block comparison uncertainty is supplied when sufficient blocks exist, with limitations otherwise.
- False-alert volume is measured only with actual coverage; scenario arithmetic is clearly hypothetical.

PRD coverage: AT-P04, AT-P05, AT-P06 and optional AT-P08.

## Stage 4 — reproducible research release

Complete the documented `run` and trusted-local `score` interfaces, final YAML/Parquet contracts, immutable artifacts, report rebuilding from saved scores, comparison chart, model card and README. Review worst-supported/worst-performing classes and experiment limitations.

Acceptance evidence:

- One documented command rebuilds the experiment after environment setup and separately completed data acquisition.
- A clean-environment smoke test creates the required artifacts; saved-model scoring matches original scores within documented tolerance.
- Reports rebuild from persisted scores without retraining; schema/version mismatches fail before inference.
- All AT-P01–AT-P07 traceability tests pass and every unresolved limitation appears in the model card/report.
- Dataset files and sensitive metadata are excluded from source control; no production-readiness or network-generalization claim is made.

Dashboard and attribution work (AT-P09) follows the core comparison and is not part of these acceptance gates.
