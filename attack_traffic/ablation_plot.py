"""Optional validation-only graphics for the fixed class-weight experiment."""

import csv
import os
from pathlib import Path


def write_ablation_chart(directory: str | Path, *, candidates=None, candidate_labels=None,
                         title="Class-weight ablation on frozen validation cohorts",
                         footer="Same forest settings; each threshold selected on validation under observed FPR ≤1%. No test scoring.") -> str:
    directory = Path(directory)
    cache = directory / ".matplotlib-cache"
    cache.mkdir(exist_ok=True)
    previous = os.environ.get("MPLCONFIGDIR")
    os.environ["MPLCONFIGDIR"] = str(cache.resolve())
    try:
        import matplotlib
        matplotlib.use("Agg")
        from matplotlib import pyplot as plt
        from matplotlib.ticker import PercentFormatter

        with (directory / "candidate_metrics.csv").open(newline="", encoding="utf-8") as stream:
            all_rows = list(csv.DictReader(stream))
        candidates = list(candidates) if candidates is not None else ["unweighted", "balanced", "balanced_subsample"]
        candidate_labels = list(candidate_labels) if candidate_labels is not None else ["Unweighted", "Balanced", "Balanced\nsubsample"]
        if not candidates or len(candidates) != len(candidate_labels):
            raise ValueError("Chart candidates and labels must be nonempty and equal length")
        variants = sorted({row["variant"] for row in all_rows}, key=lambda name: ({"original": 0, "corrected": 1}.get(name, 2), name))
        fig, axes = plt.subplots(1, max(1, len(variants)), figsize=(6 * max(1, len(variants)), 5.1), squeeze=False, layout="constrained")
        for ax, variant in zip(axes[0], variants):
            for index, candidate in enumerate(candidates):
                row = next((row for row in all_rows if row["variant"] == variant and row["candidate"] == candidate), None)
                if row is None or row["status"] != "ok":
                    ax.text(index, .002, "failed", ha="center", color="#8B302B")
                    continue
                recall, fpr = float(row["recall"]), float(row["fpr"])
                lower, upper = float(row["recall_lower_95"]), float(row["recall_upper_95"])
                ax.bar(index, recall, width=.58, color=["#758699", "#177F87", "#365D9D"][index % 3])
                ax.errorbar(index, recall, yerr=[[max(0, recall-lower)], [max(0, upper-recall)]], fmt="none", capsize=4, color="#25374C")
                ax.annotate(f"{recall:.2%}\nFPR {fpr:.2%}", (index, upper), xytext=(0, 10), textcoords="offset points", ha="center", fontsize=9)
            ax.set_xticks(range(len(candidates)), candidate_labels)
            ax.set_title(variant, fontweight="bold", loc="left")
            values = [float(row["recall_upper_95"]) for row in all_rows if row["variant"] == variant and row["status"] == "ok"]
            ax.set_ylim(0, max(.06, max(values, default=.02) * 1.45))
            ax.yaxis.set_major_formatter(PercentFormatter(1))
            ax.set_ylabel("Validation attack recall")
            ax.grid(axis="y", alpha=.2)
            ax.set_axisbelow(True)
            ax.spines[["top", "right"]].set_visible(False)
        fig.suptitle(title, x=.02, ha="left", fontsize=16, fontweight="bold")
        fig.supxlabel(footer + "\nWhiskers: flow-level Wilson 95% intervals assuming independence; temporal correlation is not modeled.", fontsize=9)
        filename = "validation_recall.png"
        fig.savefig(directory / filename, dpi=160, bbox_inches="tight", facecolor="white")
        plt.close(fig)
        return filename
    finally:
        if previous is None:
            os.environ.pop("MPLCONFIGDIR", None)
        else:
            os.environ["MPLCONFIGDIR"] = previous
