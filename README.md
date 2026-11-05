# Attack Traffic Classifier

An offline machine learning research prototype for classifying network-flow records. It compares original and corrected CICIDS2017 datasets using chronological splits, auditable preparation and random-forest baselines.

**Status: concluded research prototype.** This project is intended for learning and reproducible research. Its results do not establish production intrusion-detection performance.

## What does it do?

The pipeline audits local CSVs, creates chronological training, validation and test partitions, trains binary classifiers, selects thresholds on validation data and reports test results. It also provides family diagnostics, saved-model scoring, provenance and audit reports. It does not capture live traffic or block connections.

```text
Local flow CSVs → audit and chronological split → train → select threshold → evaluate → reports
```

The research investigates how a fixed pipeline behaves on original and corrected datasets and across captures. The two datasets are independently sampled populations, so their comparison does not isolate a causal effect of label correction.

## Results

These are exploratory paired CICIDS2017 capture-day results from deterministic 1% samples and the original unweighted baseline models. Thresholds were selected on validation data. The corrected test capture had been inspected previously, so it is not a fresh independent confirmation.

| Test metric | Original-data model | Corrected-data model |
| --- | ---: | ---: |
| Attack recall | 54.79% | 72.31% |
| False-positive rate | 0.999% | 0.792% |
| Attack recall excluding DDoS | 4.55% | 2.16% |

DDoS dominates the detected attacks. Later cross-capture experiments showed unstable transfer and sensitivity to repeated feature groups; some false-positive rates exceeded the 1% target. See the [model card](docs/MODEL-CARD.md), [Experiment 002](docs/EXPERIMENT-002.md) and [sensitivity analysis](docs/EXPERIMENT-007-SENSITIVITY-RESULTS.md).

## Features

- Audits schemas, labels, duplicate feature groups and partition boundaries.
- Uses 27 flow statistics, including packet counts, lengths, interarrival times and active/idle durations. IP addresses, ports, labels and disputed TCP flag fields are excluded from this reference feature set.
- Compares constant baselines and random forests with capture-day splits and validation-selected thresholds.
- Records class support, predictions, metrics, provenance and limitations.
- Includes small synthetic fixtures for trying the workflow without a dataset download.

## Requirements

The project declares Python 3.11 or newer. The recorded research and clean-environment checks used **Python 3.13.14 on Windows**. Windows, macOS and Linux instructions are provided below, but macOS, Linux, other Python versions and every hardware architecture have not been independently verified. Package wheels and pinned dependency compatibility may vary by platform.

You need Python, pip and a virtual environment. Internet access is needed for dependency installation unless packages are cached. Full research reproduction requires separately obtained datasets and substantial storage and compute.

## Quick start

Open a terminal in the project root. If you cloned or extracted the project into a folder named `attack-traffic-classifier`, enter that folder first.

### Windows PowerShell

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements-report.txt
.\.venv\Scripts\python.exe main.py audit --config configs/demo.json
.\.venv\Scripts\python.exe main.py run --config configs/attack-demo.yaml
```

If the Python launcher is unavailable, use a compatible `python` command to create the environment. In Windows Command Prompt, use `.venv\Scripts\python.exe` for subsequent commands.

### macOS and Linux

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements-report.txt
.venv/bin/python main.py audit --config configs/demo.json
.venv/bin/python main.py run --config configs/attack-demo.yaml
```

The audit writes to `artifacts/demo-audit/` and the example run writes to `artifacts/baseline-demo/`. Output directories are immutable: to run again, copy the relevant configuration within `configs/`, change its `output_dir` to a new path and pass that config. Paths resolve relative to the config file. Example data and metrics are synthetic.

The core audit uses the standard library. Training uses [requirements-training.txt](requirements-training.txt); [requirements-report.txt](requirements-report.txt) adds plotting and Parquet support.

## Commands and tests

Run from the project root with the virtual environment's Python. Replace `python` below with the environment path shown above if it is not activated.

```bash
python main.py --help
python main.py audit --help
python main.py run --help
python main.py score --help
python main.py report --help
python -m unittest discover -s tests -v
```

Some research tests use pytest; install it separately in the virtual environment before running `python -m pytest`. Only load trusted local model bundles. The [historical research notes](README-RESEARCH-HISTORY.md) provide detailed data preparation and experiment commands.

## Project structure

```text
attack_traffic/       Core audit, preparation, modeling and reporting
configs/              Example and research configurations
examples/             Project-authored synthetic CSV fixtures
scripts/              Research and dataset-inspection utilities
tests/                Automated checks
docs/                 Model card, experiments and release evidence
main.py               Offline command-line entry point
pyproject.toml        Project metadata and optional dependencies
requirements-*.txt    Pinned research dependency snapshots
data/                 Local datasets and manifests; excluded from version control
artifacts/            Generated outputs; excluded from version control
```

The PRD and TRD are at the project root. Dataset archives and generated outputs are not included in a clean checkout. Do not commit private data, packet captures, model bundles or large generated artifacts.

## Data and limitations

Original and corrected datasets have separate provenance and third-party terms. Obtain them from their publishers and review their terms; the project license does not grant redistribution rights. Original timestamp AM/PM and timezone ambiguity limit exact cross-release alignment. Conflicting feature groups, repeated patterns and unseen attack families limit interpretation of metrics.

The TON_IoT packet-to-flow investigation is an unfinished extension. Its experimental extractor and preflight have synthetic test evidence, but Java extractor equivalence, independent label provenance and a fresh final assessment remain open. Model scores are not calibrated real-world probabilities.

## Documentation

- [Model card and evaluation limitations](docs/MODEL-CARD.md)
- [Research release evidence](docs/RELEASE-REVIEW-2026-11-05.md)
- [TON_IoT preflight and extractor investigation](docs/EXPERIMENT-009-PREFLIGHT-AND-ACTIVE-STD-RESULTS.md)
- [Product requirements](PRD-01-attack-traffic-classifier.md) and [technical requirements](TRD-01-attack-traffic-classifier.md)
- [Historical research notes and detailed commands](README-RESEARCH-HISTORY.md)

## License

Project-authored code is licensed under the [MIT License](LICENSE), copyright Maahin Bir Singh Osahan. Third-party datasets and software have their own terms.
