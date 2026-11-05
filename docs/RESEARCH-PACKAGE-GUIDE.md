# Research package guide

This source package supports an offline, research-only intrusion-detection comparison. Start with `README.md`, the [PRD](../PRD-01-attack-traffic-classifier.md), [TRD](../TRD-01-attack-traffic-classifier.md), [model card](MODEL-CARD.md), and [release review](RELEASE-REVIEW-2026-11-05.md).

## What is included

The package includes Python source, experiment scripts, test code, configurations, documentation, and project-authored synthetic CSV fixtures. A SHA-256 manifest lists packaged files. Several historical documents reference local `data/` or `artifacts/` paths: those files were intentionally not packaged, and links to them will not resolve in a fresh extraction. Some research and packet-analysis scripts require separately obtained datasets or saved artifacts and are not portable standalone demonstrations.

No real datasets, packet captures, trained model bundles, row-level results, or serialized artifacts are included. The numeric findings quoted in documentation are research summaries, not executable evidence of the underlying experiments. Project-authored code is offered under the included MIT license; this does not change licenses or terms for third-party dependencies, datasets, or derived records. Obtain the original data separately through its source and follow its stated terms.

## Synthetic smoke run on Windows

From a PowerShell window in the freshly extracted package, with Python 3.13 installed:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-report.txt
.\.venv\Scripts\python.exe main.py run --config configs/attack-demo.yaml
.\.venv\Scripts\python.exe main.py report --run artifacts/baseline-demo --output artifacts/synthetic-report --charts --parquet
```

The commands need package-index access or suitable cached wheels. The sample input is invented; its scores are not model-quality results. Each run refuses to overwrite an existing output directory. For another run, copy the YAML to a new file **in `configs/`**, choose a fresh `output_dir`, and use a fresh report destination. Relative dataset paths resolve against the config's directory. Only deserialize trusted local model bundles; joblib loading can execute code.

Direct dependencies are version-pinned in the requirements files, but not every transitive dependency is pinned. A prior clean-virtual-environment smoke test and its exact resolved versions are described in [the smoke record](CLEAN-ENVIRONMENT-SMOKE-2026-11-05.md); its local JSON artifact is not included in this package. The test shared the host operating system and Python installation.

## Interpretation

The original/corrected comparison uses separate deterministic 1% samples and capture-day partitions, not one-to-one matched flows. Original timestamps have unresolved AM/PM and timezone. The corrected test capture was examined previously. The models' strong aggregate test recall is heavily driven by DDoS, and many unseen attacks are poorly detected. The later external assessment was consumed and cannot serve as a new final holdout. The shared 27-feature policy excludes disputed TCP flag counts. Do not use these results to claim operational readiness or a causal benefit from label corrections.

Before publishing or redistributing a package, separately review third-party licensing, dataset/derived-data rights, its contents, and the accuracy of the accompanying claims. No publication or external distribution is performed by preparing this local package.
