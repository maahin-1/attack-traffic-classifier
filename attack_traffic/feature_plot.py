"""Validation-only view of the preregistered 27-versus-39 feature comparison."""

from pathlib import Path

from .ablation_plot import write_ablation_chart


def write_feature_chart(directory: str | Path) -> str:
    return write_ablation_chart(
        directory,
        candidates=["baseline27", "expanded39"],
        candidate_labels=["27 features", "39 features"],
        title="Feature block ablation on frozen validation cohorts",
        footer="Same balanced-subsample forest policy; max_features='sqrt' considers 5 versus 6 columns per split.\nEach threshold uses validation under observed FPR ≤1%. No test scoring or duplicate-policy changes.",
    )
