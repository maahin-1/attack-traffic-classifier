"""Static, exportable charts derived from verified report CSVs."""

from __future__ import annotations

import csv
import os
from pathlib import Path


def _read(path):
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def write_charts(directory: str | Path) -> list[str]:
    """Render test recall/support and confusion counts; never score a model."""
    directory = Path(directory)
    # Confine Matplotlib's cache to the report stage on restricted Windows hosts.
    cache = directory / ".matplotlib-cache"
    cache.mkdir(exist_ok=True)
    previous_cache = os.environ.get("MPLCONFIGDIR")
    os.environ["MPLCONFIGDIR"] = str(cache.resolve())
    try:
        import matplotlib
        matplotlib.use("Agg")
        from matplotlib import pyplot as plt
        from matplotlib.patches import Patch
        from matplotlib.ticker import PercentFormatter

        classes = [row for row in _read(directory / "per_class.csv") if row["model"] == "random_forest" and row["binary_detection_recall"] != ""]
        metrics = [row for row in _read(directory / "metrics.csv") if row["partition"] == "test" and row["model"] == "random_forest"]
        variants = sorted({row["variant"] for row in metrics}, key=lambda value: ({"original": 0, "corrected": 1}.get(value, 2), value))
        if not variants:
            raise ValueError("No verified random-forest test metrics available for charts")
        fig, axes = plt.subplots(len(variants), 1, figsize=(12, max(5.6, 5.6 * len(variants))), squeeze=False, layout="constrained")
        for ax, variant in zip(axes[:, 0], variants):
            rows = sorted([row for row in classes if row["variant"] == variant and int(row["test_support"]) > 0], key=lambda row: -int(row["test_support"]))
            if not rows:
                ax.text(.5, .5, "No attack-family test support", ha="center", transform=ax.transAxes)
                continue
            names = [row["family"] for row in rows]
            values = [float(row["binary_detection_recall"]) for row in rows]
            ax.barh(range(len(rows)), values, color="#177F87", height=.58)
            for index, (row, value) in enumerate(zip(rows, values)):
                ax.scatter(value, index, color="#0A4F56", s=24, zorder=3)
                label = f"{value:.1%}   |   test n={row['test_support']}, train n={row['training_support']}"
                ax.text(1.035, index, label, va="center", fontsize=9)
            ax.set_yticks(range(len(rows)), names, fontsize=10)
            ax.invert_yaxis()
            ax.set_xlim(0, 1.01)
            ax.xaxis.set_major_formatter(PercentFormatter(1))
            ax.set_xlabel("Binary attack detection recall at the frozen validation threshold")
            ax.set_title(f"{variant}: test recall by attack family", loc="left", fontweight="bold", pad=15)
            ax.grid(axis="x", alpha=.2)
            ax.set_axisbelow(True)
            ax.spines[["top", "right"]].set_visible(False)
        fig.suptitle("Attack detection by family", x=.02, ha="left", fontsize=17, fontweight="bold")
        fig.supxlabel("Only families observed in test are plotted. Unobserved families have null recall in per_class.csv.\nTraining support is shown; an unseen family cannot be learned by the family classifier.", fontsize=9)
        fig.savefig(directory / "recall_by_family.png", dpi=160, bbox_inches="tight", facecolor="white")
        plt.close(fig)

        fig, axes = plt.subplots(1, len(variants), figsize=(5.4 * len(variants), 4.8), squeeze=False, layout="constrained")
        for ax, variant in zip(axes[0], variants):
            row = next(row for row in metrics if row["variant"] == variant)
            counts = [[int(row["tn"]), int(row["fp"])], [int(row["fn"]), int(row["tp"])]]
            ax.imshow(counts, cmap="Blues", vmin=0)
            maximum = max(value for pair in counts for value in pair)
            for actual in range(2):
                for predicted in range(2):
                    value = counts[actual][predicted]
                    ax.text(predicted, actual, f"{value:,}", ha="center", va="center", fontsize=17, color="white" if value > maximum * .55 else "#17334F")
            ax.set_xticks([0, 1], ["Predicted benign", "Predicted attack"])
            ax.set_yticks([0, 1], ["Actual benign", "Actual attack"])
            ax.set_title(f"{variant}: random-forest test counts", fontweight="bold", pad=14)
        fig.supxlabel("Frozen thresholds; counts describe the configured population, not enterprise-network performance.", fontsize=9)
        fig.savefig(directory / "test_confusion.png", dpi=160, bbox_inches="tight", facecolor="white")
        plt.close(fig)
        written = ["recall_by_family.png", "test_confusion.png"]
        if len(variants) >= 2:
            family_names = sorted({row["family"] for row in classes if int(row["test_support"]) > 0})
            if family_names:
                fig, ax = plt.subplots(figsize=(13, max(5.5, len(family_names) * .65)), layout="constrained")
                lookup = {(row["variant"], row["family"]): row for row in classes}
                width = .72 / len(variants)
                colors = ["#365D9D", "#177F87", "#B16B26", "#8F4A82"]
                labels = []
                for family in family_names:
                    supports = ", ".join(f"{variant} n={lookup.get((variant, family), {}).get('test_support', '0')}" for variant in variants)
                    labels.append(f"{family}\n{supports}")
                for offset, variant in enumerate(variants):
                    for index, family in enumerate(family_names):
                        row = lookup.get((variant, family))
                        y = index - .36 + width / 2 + offset * width
                        if row is None or row["binary_detection_recall"] == "" or int(row["test_support"]) == 0:
                            ax.text(.012, y, "n/a", color="#777777", fontsize=8, va="center")
                        else:
                            value = float(row["binary_detection_recall"])
                            ax.barh(y, value, height=width * .9, color=colors[offset % len(colors)])
                            ax.scatter(value, y, color=colors[offset % len(colors)], s=14, zorder=3)
                ax.set_yticks(range(len(family_names)), labels, fontsize=9)
                ax.invert_yaxis()
                ax.set_xlim(0, 1.01)
                ax.xaxis.set_major_formatter(PercentFormatter(1))
                ax.set_xlabel("Test binary attack detection recall")
                ax.set_title("Original / corrected population comparison by family", loc="left", fontweight="bold", pad=16)
                ax.legend(handles=[Patch(facecolor=colors[index % len(colors)], label=variant) for index, variant in enumerate(variants)], loc="lower right")
                ax.grid(axis="x", alpha=.2)
                ax.set_axisbelow(True)
                ax.spines[["top", "right"]].set_visible(False)
                fig.supxlabel("Each model uses its validation-frozen threshold. Independently sampled populations; not label-only causal effects.\nTest support is shown beside each family. n/a means no test support; small n cannot establish reliable family performance.", fontsize=9)
                fig.savefig(directory / "recall_comparison.png", dpi=160, bbox_inches="tight", facecolor="white")
                plt.close(fig)
                written.append("recall_comparison.png")
        return written
    finally:
        if previous_cache is None:
            os.environ.pop("MPLCONFIGDIR", None)
        else:
            os.environ["MPLCONFIGDIR"] = previous_cache
