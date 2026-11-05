# Requirements review

Reviewed 2 November 2026 against PRD 01 and TRD 01, both version 1.0.

The specifications support implementation of the offline audit foundation now. A defensible real-data experiment requires the decisions below before model fitting. No dataset release, license, performance result or model quality is approved by this review.

| Area | Finding | Required decision or evidence |
| --- | --- | --- |
| Corrected release | The cited WTMC2021 page lists multiple regenerated uploads and links the later CNS2022 work. “Corrected CICIDS2017” is insufficient identification. | Select a publication/release lineage; record source, exact filenames, retrieval timestamp, license/reference and SHA-256 for every local file. A subsequent release is a new experiment lineage. |
| Original schema | No local real dataset was supplied. The presence of usable event timestamps, duration units and equivalent feature definitions is unverified. | Inspect actual original and corrected headers and representative values. Reject a timestamp-free export for the chronological experiment; do not infer event times from row position. |
| Time semantics | CNS2022 tool documentation states UTC timestamps with microsecond precision. That does not establish the original export's timezone. | Declare each adapter's timestamp format, timezone and duration unit. Normalize boundaries to a common timeline; quarantine spanning flows and disclose unavailable end times. Resolve ambiguous dates explicitly. |
| Attempted attacks | PRD/TRD require preserving attempted/effective distinctions, but do not settle the learning target for attempted flows. CNS2022 download guidance recommends benign mapping when unsure and rejects attempted flows as a separate model class. | Preserve raw labels/categories in audit metadata. Version an explicit binary/family mapping and rationale before fitting; do not silently create attempted-family model classes. |
| Feature intersection | Equal column names do not guarantee equal units or extraction semantics across releases. | Document canonical name, unit and meaning; use the same vetted intersection for both variants. Exclude all identifiers and label-derived columns, including attempted categories. |
| Duplicate policy | “Later copies” needs an ordering and scope definition. Feature-only equality can group genuinely different flows and conflicting labels. | Define per-variant canonical-feature hashes and earliest-event retention, with a deterministic equal-time tie rule. Quarantine later copies and report conflicting-label groups. Never deduplicate across the two variants as though their rows were matched. |
| Split support | Early chronological periods may be benign-only. An arbitrary date split can make fitting or threshold selection invalid. | Inventory retained binary/family support per candidate partition before freezing boundaries. Require both binary classes in training and validation before fitting/threshold selection. Preserve unseen test classes. |
| Comparison claim | Regenerated flows change the population as well as labels. | Describe the main result as a data-version/pipeline comparison. Label-only effects require a separately verified matched cohort, matching evidence and unmatched counts. |
| License and redistribution | A public download link does not establish redistribution rights. No license was verified in this review. | Review the selected files' terms before acquisition/use; retain references. Keep real datasets, raw network identifiers and serialized artifacts out of source control. |
| Scale and resources | Chunked CSV reading alone does not bound a Python duplicate-hash set. No hardware/runtime evidence exists yet. | Benchmark representative local data; record peak memory, throughput and elapsed time. Use a disk-backed dedup index or document a measured subset limit before calling full-data ingestion memory-bounded. |

## Foundation boundary

The first implementation is a Python standard-library audit command with explicit adapters/configuration, synthetic fixtures, provenance, row accounting, feature guards and chronological split evidence. JSON configuration and CSV split exports are a temporary foundation interface; the TRD's YAML, Parquet, training, scoring and report-reconstruction contracts remain later work. Synthetic success does not establish real-release adapter compatibility or satisfy the complete MVP acceptance gate.

Before stage 2, verify `input = retained + excluded + quarantined` per variant and class, review every exclusion category, and inspect train/validation/test support. Unknown labels, schema errors and inconsistent timing assumptions must fail visibly rather than becoming benign observations.

## Sources checked

- [WTMC2021 tools and datasets](https://intrusion-detection.distrinet-research.be/WTMC2021/tools_datasets.html): regenerated uploads, changes to flow construction, and link to subsequent work.
- [CNS2022 project](https://intrusion-detection.distrinet-research.be/CNS2022/index.html): later dataset recreation and documentation.
- [CNS2022 download guidance](https://intrusion-detection.distrinet-research.be/CNS2022/Dataset_Download.html): attempted-flow target guidance.
- [CNS2022 tools documentation](https://intrusion-detection.distrinet-research.be/CNS2022/Tools_Documentation.html): UTC timestamp output and additional feature changes.

These pages were read on 2 November 2026; no dataset archive was downloaded or inspected.
