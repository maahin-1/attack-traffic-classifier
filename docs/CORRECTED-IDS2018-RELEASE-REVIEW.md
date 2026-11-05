# Regenerated CSE-CIC-IDS2018 release review

Reviewed 3 November 2026. Decision: the CNS2022 regenerated release is a suitable candidate for a development data-contract inspection, but it does not yet pass Experiment 006's provenance/coverage gates or constitute a new independent capture. No model was fitted or scored and no complete dataset was downloaded.

## Archive and schema verified remotely

Official [archive directory](https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/) links a single `CSECICIDS2018_improved.zip`. HTTP HEAD reports **10,426,851,729 bytes** (10.43 GB / about 9.71 GiB), last modified 3 April 2023 14:53:27 GMT. ZIP directory metadata claims **36,044,466,483 uncompressed bytes** across ten CSVs. Keeping the ZIP and all extracted CSVs would require about **46.47 GB**, before staging, derived data and models. This is an estimate from directory entries, not a verified extraction.

Bounded HTTP range requests transferred **5,314 bytes** in total, reading the ZIP directory and the first line of the designated development CSV. The directory includes 14, 15, 16, 20, 21, 22, 23 and 28 February, plus 1 and 2 March 2018. It claims the 14 February development member is 930,748,488 compressed bytes and 3,262,583,806 uncompressed bytes. The directory sizes do not establish row counts, clock coverage or capture completeness.

The 14 February header has **91 unique columns** and contains every one of the 27 source names in the existing corrected-2017 `FEATURES` mapping, plus `Label`, `Attempted Category` and explicit identifiers. Inputs can therefore be mapped without inventing aliases, but all-day schema consistency, numeric validity, time interpretation and actual feature semantics still require inspection. Identifier, attempted-category and label columns remain excluded from model inputs. Only the development header was read; later members were not decompressed or scored. No full archive SHA-256 or member CRC has been verified. The ETag is not treated as an authenticated checksum.

Machine-readable evidence and bounded inspection script: `artifacts/corrected2018-remote-inventory.json` and `artifacts/inspect-corrected2018-remote.py`. The script refuses large reads, enforces HTTP 206/content ranges and caps total metadata transfer at 2 MiB. It uses Python's ZIP parser, including ZIP64 support.

## Extraction and labels

The [authors' reproduction repository](https://github.com/GintsEngelen/CNS2022_Code) describes removing one duplicated prior-day PCAP, repairing/reordering raw PCAPs, processing each day with their modified flow meter at flow/activity timeouts of 120,000,000 / 5,000,000, and applying the fixed 2018 labeling notebook. This is regeneration from raw traffic, not merely replacing labels in the original ML CSVs. Its extractor link is floating; inspected sources do not identify the exact commit/configuration that produced the hosted archive. Pinning a current code snapshot would document today's inspection, not prove historical production provenance.

The [tool documentation](https://intrusion-detection.distrinet-research.be/CNS2022/Tools_Documentation.html) describes revised TCP termination, UTC microsecond timestamps, directional RST fields, ICMP support and a segmentation-offset fix. These changes support a more explicit measurement lineage but change flow reconstruction and populations. The matched header does not establish one-to-one alignment with the old exports or remove every semantic uncertainty.

The [2018 correction documentation](https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html) provides traffic-based relabeling rules, including ineffective attacks and attempted flows, plus small subsequent corrections. These are documented analyst judgments, not infallible ground truth. The archive's April 2023 date and website update notes must be recorded as a specific snapshot rather than assuming one canonical release forever. Under the [download guidance](https://intrusion-detection.distrinet-research.be/CNS2022/Dataset_Download.html), attempted flows should not become a separate ML target; our proposed binary contract maps them to benign while preserving raw labels and categories in audit evidence, consistent with the existing corrected-2017 policy. Freeze that choice before outcomes.

## Experiment 006 decision and next concrete slice

1. Inspect the **14 February development member only**, either through bounded member-range acquisition (about 931 MB compressed plus 3.26 GB if stored extracted) or a full archive download if broader inspection justifies the 10.43 GB transfer. Verify member CRC after complete decompression, calculate local hashes, and record byte ranges/source identity. Do not claim a verified whole-archive hash from member-only acquisition.
2. Inventory schema, labels, dates, durations, invalid values and complete row accounting. Compare measurement distributions against the corrected-2017 contract without tuning a model. Establish actual CSV row/time coverage and retain remaining PCAP-coverage uncertainty explicitly. Keep unused members protected from model outcomes.
3. Pin available labeling/extractor source snapshots and pursue evidence tying the archive to a producer version. If no historical tie can be established, explicitly choose a qualified cross-version experiment or regenerate both inputs with one pinned extractor; do not label it exact parity.
4. Only after these gates are reviewed, instantiate the documented Wednesday-support experiment. Any corrected version of 15/16 February remains the same underlying already examined capture, so it cannot become a fresh holdout simply through relabeling. An unexamined block from this release would still share the generated testbed; a different capture environment is preferable for stronger final claims.

This review selects an inspectable source, not a trained candidate or completed coverage certification. Full archive acquisition is not necessary to begin the development-member inspection.

The development-member acquisition and full inventory are now complete; see [inventory findings](CORRECTED-IDS2018-DEVELOPMENT-INVENTORY.md). Member size, CRC and local SHA-256 are verified, and 5,898,350 rows were inventoried without model scoring. The full archive remains unacquired and historical producer/capture-completeness gates remain open.
