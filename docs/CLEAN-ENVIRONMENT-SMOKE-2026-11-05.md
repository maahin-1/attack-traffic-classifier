# Clean-environment synthetic smoke test — 5 November 2026

## Outcome

A newly created project-local Python 3.13.14 virtual environment with `include-system-site-packages = false` installed the top-level pinned packages in `requirements-report.txt`. The smoke process also set `PYTHONNOUSERSITE=1`. `pip check` reported no broken requirements. The environment reuses the host Python interpreter and operating system; it is not a clean OS or a separate machine.

The synthetic fixture ran end to end from a generated configuration, and the `report` command rebuilt the reports from persisted run artifacts with both `--charts` and `--parquet`. The output contains PNG charts, Parquet exports, comparison and metric tables, and Markdown reports. For each of the two synthetic variants, all **two** saved-model test scores and associated prediction metadata matched the run's saved predictions using an absolute tolerance of `1e-14`. This establishes a small workflow check, not real-data performance or broad parity across the real dataset.

The machine-readable [smoke evidence](../artifacts/clean-release-check-20261105/report.json) records the interpreter, resolved package versions, `pip check`, command outputs and parity counts. The [fixture run](../artifacts/clean-release-fixture-20261105/report.md) and [rebuilt report](../artifacts/clean-release-report-20261105/report.md) are separate immutable outputs. The runner is [release_smoke_20261105.py](../scripts/release_smoke_20261105.py). The synthetic feature and score files contain no actual network traffic.

## Installation and reproducibility scope

The sandbox initially prevented `ensurepip` from writing to its default temporary directory. Setting `TEMP` and `TMP` to a project-local temporary directory allowed the existing environment to be completed. A restricted-network pip attempt could not resolve PyPI; the installation succeeded with authorized network access, using both cached wheels and downloaded dependencies. No system site-packages were included in the virtual environment.

`requirements-training.txt` and `requirements-report.txt` pin direct dependencies but do **not** pin every transitive dependency. The complete versions resolved in this run are recorded in the smoke evidence; a future installation may resolve a different transitive set. The runner uses the source checkout directly and does not demonstrate a wheel or editable project installation. Its output paths are fixed and refuse overwriting, so a repeat must use fresh output paths.

This closes the synthetic clean-virtual-environment workflow check in the current release review. It does not complete the requirement-by-requirement release review, prove a fresh full-data run, validate data labels, establish model generalization, or turn the consumed assessment capture into a new holdout. Disputed cross-release flag features remain excluded.
