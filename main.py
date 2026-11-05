"""Command-line entry point for the offline research pipeline."""

import argparse
import sys

from attack_traffic import run_audit


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline flow audit, training, and trusted-local scoring.")
    commands = parser.add_subparsers(dest="command", required=True)
    audit = commands.add_parser("audit", help="Validate, clean, and partition local CSV files")
    audit.add_argument("--config", required=True, help="Path to a version 1 JSON or YAML configuration")
    run = commands.add_parser("run", help="Audit local data, fit baselines, and evaluate frozen thresholds")
    run.add_argument("--config", required=True)
    score = commands.add_parser("score", help="Score canonical features using a trusted local model bundle")
    score.add_argument("--model", required=True, help="Trusted local model directory")
    score.add_argument("--input", required=True, help="CSV containing canonical model features")
    score.add_argument("--output", required=True)
    report = commands.add_parser("report", help="Verify saved scores and rebuild reports without retraining")
    report.add_argument("--run", required=True, help="Existing immutable experiment directory")
    report.add_argument("--output", required=True, help="New report directory")
    report.add_argument("--charts", action="store_true", help="Export PNG charts (requires Matplotlib)")
    report.add_argument("--parquet", action="store_true", help="Export split/prediction Parquet files (requires PyArrow)")
    inspect_original = commands.add_parser("inspect-original", help="Inventory positional original CSV schemas, labels and unresolved clocks")
    prepare_original = commands.add_parser("prepare-original", help="Prepare an audited capture-date subset from the original ZIP")
    for command in (inspect_original, prepare_original):
        command.add_argument("--archive", required=True)
        command.add_argument("--acquisition", required=True)
        command.add_argument("--output", required=True)
    prepare_original.add_argument("--denominator", type=int, default=100)
    prepare_original.add_argument("--max-rows", type=int, default=50000)
    collisions = commands.add_parser("audit-collisions", help="Diagnose feature-equivalence groups without changing the benchmark")
    collisions.add_argument("--run", required=True)
    collisions.add_argument("--output", required=True)
    weights = commands.add_parser("tune-weights", help="Compare three fixed class-weight choices using training/validation only")
    weights.add_argument("--run", required=True)
    weights.add_argument("--output", required=True)
    weights.add_argument("--chart", action="store_true", help="Export a validation-only recall chart (requires Matplotlib)")
    extract = commands.add_parser("extract-features", help="Join a fixed extra feature block to frozen train/validation records")
    extract.add_argument("--run", required=True)
    extract.add_argument("--original-archive", required=True)
    extract.add_argument("--original-acquisition", required=True)
    extract.add_argument("--corrected-archive", required=True)
    extract.add_argument("--corrected-acquisition", required=True)
    extract.add_argument("--output", required=True)
    feature_run = commands.add_parser("ablate-features", help="Compare 27 vs 39 features on unchanged train/validation cohorts")
    feature_run.add_argument("--run", required=True)
    feature_run.add_argument("--features", required=True, help="Verified extra-feature extraction directory")
    feature_run.add_argument("--output", required=True)
    feature_run.add_argument("--chart", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "audit":
            output = run_audit(args.config)
        elif args.command == "run":
            from attack_traffic.train import run_experiment

            output = run_experiment(args.config)
        elif args.command == "score":
            from attack_traffic.model import score_model

            output = score_model(args.model, args.input, args.output)
        elif args.command == "report":
            from attack_traffic.report import rebuild_report

            output = rebuild_report(args.run, args.output, charts=args.charts, parquet=args.parquet)
        elif args.command == "inspect-original":
            from attack_traffic.original import inspect_original as inspect_archive

            output = inspect_archive(args.archive, args.acquisition, args.output)
        elif args.command == "prepare-original":
            from attack_traffic.original import prepare_original_subset

            output = prepare_original_subset(args.archive, args.acquisition, args.output, args.denominator, args.max_rows)
        elif args.command == "audit-collisions":
            from attack_traffic.collision_audit import audit_collisions

            output = audit_collisions(args.run, args.output)
        elif args.command == "tune-weights":
            from attack_traffic.tune import run_weight_ablation

            output = run_weight_ablation(args.run, args.output, charts=args.chart)
        elif args.command == "extract-features":
            from attack_traffic.feature_extract import extract_features

            output = extract_features(args.run, args.original_archive, args.original_acquisition, args.corrected_archive, args.corrected_acquisition, args.output)
        else:
            from attack_traffic.feature_ablation import run_feature_ablation

            output = run_feature_ablation(args.run, args.features, args.output, charts=args.chart)
    except (ValueError, OSError) as error:
        print(f"{args.command.capitalize()} failed: {error}", file=sys.stderr)
        return 1
    except ImportError as error:
        print(f"Missing dependency: {error}. Install the project's training dependencies.", file=sys.stderr)
        return 1
    print(f"{args.command.capitalize()} artifacts: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
