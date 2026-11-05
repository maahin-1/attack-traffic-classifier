"""Build a matched capture-day comparison config from inspected local subsets."""

from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path

from .audit import _validate
from .config import load_config


def build_paired_config(original_dir: str | Path, corrected_dir: str | Path,
                        output_config: str | Path, run_output: str | Path) -> Path:
    output_config = Path(output_config).resolve()
    if output_config.exists():
        raise ValueError(f"Paired config already exists: {output_config}")
    configurations = []
    for folder, expected in ((original_dir, "original"), (corrected_dir, "corrected")):
        folder = Path(folder).resolve()
        config = load_config(folder / "config.json")
        _validate(config)
        if config.get("temporal_basis") != "capture_date" or config.get("profile") != "subset":
            raise ValueError("Paired preparation requires explicit capture_date subset configurations")
        if len(config["datasets"]) != 1 or config["datasets"][0]["variant"] != expected:
            raise ValueError(f"Expected exactly one {expected} dataset in its preparation")
        for path in config["datasets"][0]["files"]:
            if not (folder / path).is_file():
                raise ValueError(f"Prepared input is missing: {folder / path}")
        configurations.append((folder, config))
    original, corrected = [item[1] for item in configurations]
    for field in ("feature_allowlist", "feature_units", "boundaries", "training"):
        if original.get(field) != corrected.get(field):
            raise ValueError(f"Paired preparation disagrees on shared control: {field}")
    first_preparation = original["datasets"][0].get("preparation", {})
    second_preparation = corrected["datasets"][0].get("preparation", {})
    denominator = first_preparation.get("denominator")
    if type(denominator) is not int or denominator < 1 or denominator != second_preparation.get("denominator"):
        raise ValueError("Paired subsets must use the same declared sampling denominator")
    algorithm = first_preparation.get("algorithm")
    if not isinstance(algorithm, str) or not algorithm.strip() or algorithm != second_preparation.get("algorithm"):
        raise ValueError("Paired subsets must use the same declared sampling algorithm")
    config = copy.deepcopy(corrected)
    config["output_dir"] = os.path.relpath(Path(run_output).resolve(), output_config.parent)
    config["label_map_version"] = "paired-release-specific-family-mappings-v1"
    config["datasets"] = []
    for folder, source in configurations:
        dataset = copy.deepcopy(source["datasets"][0])
        for field in ("label_map", "label_map_version", "timezone", "timestamp_format"):
            dataset[field] = copy.deepcopy(dataset.get(field, source.get(field)))
        dataset["files"] = [os.path.relpath((folder / path).resolve(), output_config.parent) for path in dataset["files"]]
        config["datasets"].append(dataset)
    config["experiment_notes"] = [
        "Exploratory comparison of independently sampled original and CNS2022 populations; not matched flow pairs or label-only causal effects.",
        "The corrected test scores were inspected in Experiment 001. This comparison reuses that capture; it is not an untouched prospective holdout. No settings are retuned from these test scores.",
        "Both releases use the same 27 numeric feature definitions/units and capture-day blocks, with one fixed forest configuration and separately validation-selected frozen thresholds.",
        "Original missing AM/PM and timezone are preserved as local uncertainty bounds; capture_date matching does not establish identical UTC-instant boundaries or within-day earliest duplicate order.",
        "Every source empty record is listed in the original preparation exclusion ledger; source padding is separate from sampled flow-quality exclusions.",
        "Later feature duplicates are quarantined by earliest eligible capture day then source order. Conflicting raw/binary-label duplicate row counts are disclosed in the audit.",
        "Test spans only two capture days; no reliable temporal-block comparison interval is claimed. Flow-level Wilson intervals assume independence."
    ]
    _validate(config)
    for dataset in config["datasets"]:
        adapter = dict(config, datasets=[dataset])
        for field in ("label_map", "label_map_version", "timezone", "timestamp_format"):
            adapter[field] = dataset[field]
        _validate(adapter)
    output_config.parent.mkdir(parents=True, exist_ok=True)
    with output_config.open("x", encoding="utf-8") as stream:
        json.dump(config, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")
    return output_config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original", required=True)
    parser.add_argument("--corrected", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    print(build_paired_config(args.original, args.corrected, args.config, args.output))


if __name__ == "__main__":
    main()
