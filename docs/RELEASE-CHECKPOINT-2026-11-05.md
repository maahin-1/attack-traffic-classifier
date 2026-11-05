# Research release checkpoint — 5 November 2026

This is an evidence inventory, not a release certification. The [PRD](../PRD-01-attack-traffic-classifier.md) requires AT-P01–AT-P07, and the [TRD](../TRD-01-attack-traffic-classifier.md) also requires a clean-environment smoke test and scoring parity. The 2 November [requirements review](REQUIREMENTS-REVIEW.md) predates subsequent acquisition and experiments and should be read as historical.

| Requirement | Existing evidence | Release check still needed |
| --- | --- | --- |
| AT-P01: provenance and row counts | [Experiment 002](EXPERIMENT-002.md), dataset manifests and preparation audits record selected releases and counts. | Reconcile final report and manifest against both release archives and document redistribution terms. |
| AT-P02: identifier exclusion | The fixed 27-feature policy, audit and feature-related tests exclude identifiers and labels. | Verify the exact final model bundles and exported feature lists; continue excluding the disputed flag block. |
| AT-P03: chronological partition and class coverage | Capture-day split and boundary/duplicate policies are documented in [model card](MODEL-CARD.md). | Verify final split evidence and prominently disclose unresolved original AM/PM and timezone; exact UTC chronology is not established. |
| AT-P04: binary and family diagnostics | The existing pipeline and model card report binary results and unseen-family limits. | Check final exports retain unseen support and do not imply a closed-set model learned absent classes. |
| AT-P05: original/corrected comparison | [Experiment 002](EXPERIMENT-002.md) reports the comparison on independent 1% samples. | Verify wording describes different populations and does not claim a causal label-only effect. |
| AT-P06: metrics and class support | Existing report artifacts include confusion counts, recall, FPR, precision at 100 and class support. | Review final tables, low support, time coverage and false-alert assumptions; note newer [external sensitivity results](EXPERIMENT-007-SENSITIVITY-RESULTS.md). |
| AT-P07: reproducible reports | The [clean virtual-environment smoke test](CLEAN-ENVIRONMENT-SMOKE-2026-11-05.md) reproduced the synthetic fixture, rebuilt charts and Parquet exports, and checked saved-model parity for two test rows per variant. | Review the documented command and artifact contract for release. The test shares the host Python and OS, is fixture-only, and transitive dependencies remain unpinned. |

On this machine, `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q --basetemp=.test-tmp/full-suite-20261105` passed **209 tests and 117 subtests** on 5 November 2026. This is a current-environment test result, separate from the clean-virtual-environment synthetic smoke test and not proof of production performance. The clean installation used cached and downloaded packages; offline installation has not been established.

The assessment capture has been consumed, and no new independent final assessment has been completed. The [rare-flag investigation](EXPERIMENT-008-RARE-FLAG-MATCH-RESULTS.md) does not validate a flag remapping. Package and publish only after completing the checks above; research claims must retain the documented limits.
