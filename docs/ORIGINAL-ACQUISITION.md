# Original CICIDS2017 acquisition evidence

Updated 2 November 2026. **Original archive acquired after the user completed publisher registration. Publisher MD5 and all ZIP member CRCs match; SHA-256 recorded.** The agent did not submit registration details or use a mirror. Historical access findings below describe the earlier unauthenticated session.

## Verified local acquisition

The registered browser exposed `CSVs/GeneratedLabelledFlows.zip` and its `.md5` file. Both downloaded from the publisher. The archive transfer completed in the background after the browser tool timed out; a later blocked navigation did not invalidate the completed file. The project copy was verified independently rather than treating the navigation failure as a failed transfer.

- Local archive: `data/original/GeneratedLabelledFlows.zip`.
- Download URL: `https://cicresearch.ca/CICDataset/CIC-IDS-2017/download.php?file=CIC-IDS-2017%2FCSVs%2FGeneratedLabelledFlows.zip` (requires the registered publisher session).
- Archive size: **283,876,488 bytes**.
- Publisher and computed MD5: `5ca3f8f69e3514950681615824149973`.
- SHA-256: `7bdbef286f8893f31c6db12105fa097fa5c2dcc6733179037a08129d150ea27a`.
- All ZIP member CRC checks passed. Eight CSV files and one directory entry are present; total uncompressed CSV bytes: **1,203,105,382**.
- Local evidence: `data/original/acquisition.json`, `GeneratedLabelledFlows.md5`, and `schema-inspection.json`. No endpoint identifiers or registration details were exported into these records.

Initial inspection confirmed **85 columns**, including timestamps and the duplicated normalized `Fwd Header Length` header in every CSV. Monday's first timestamp contains seconds (`03/07/2017 08:55:58`); other first records use minute precision without AM/PM (for example, the Thursday afternoon file starts at `6/7/2017 1:00`). Subsequent full inventory found 2,830,743 nonempty flows plus 288,602 empty source records. Both duplicated-header columns are equal and are omitted. The [original adapter](ORIGINAL-ADAPTER.md) and [capture-day comparison](EXPERIMENT-002.md) are complete, while the missing UTC/AM-PM information remains explicitly unresolved. No full CSV extraction or model training was performed during acquisition itself.

## Publisher access route

The [UNB dataset page](https://www.unb.ca/cic/datasets/ids-2017.html) names `GeneratedLabelledFlows.zip` and `MachineLearningCSV.zip` and links the [CIC download portal](https://cicresearch.ca/CICDataset/CIC-IDS-2017/). GeneratedLabelledFlows is the candidate for the chronological experiment; actual timestamps and headers still need inspection after acquisition. The capture-day sizes on the UNB page are not verified CSV archive sizes and must not be used as a download estimate.

Read-only inspection of public portal HTML and JavaScript established:

- The form posts to `insert.php`. Required fields are First Name, Last Name, Email, Organization/Company, Job Title and Country; Organization/Company has a 100-character maximum.
- File browsing is offered after the registration response reports success. The public JavaScript uses the returned redirect, with `browse.php` as fallback.
- A plain unauthenticated GET to `https://cicresearch.ca/CICDataset/CIC-IDS-2017/browse.php` returned **HTTP 403 Forbidden**. No parameters were enumerated, no registration state was forged, and no further gated resource access was attempted.
- The server-error notice and retry link are **initially hidden page templates**. A text-only parser exposed their text, which earlier notes interpreted as a live failure. That interpretation was incorrect: without submitting the form, registration-service availability remains unknown. “Open browse page again” initially points to `#`; its handler is installed after successful registration.

The public landing page, form and script expose no verified direct archive link, byte count or checksum. A third-party mirror may offer historical copies but would add a separate provenance decision; none has been substituted.

Registration, acquisition, positional inventory and explicit duplicate-column handling are now complete. The original timestamp ambiguity is preserved as intervals for the qualified capture-day experiment. No personal form values belong in project config or logs.

## Feature-semantic preparation

The current corrected-only policy contains 27 numeric features in `attack_traffic/prepare.py`. The source comparison below is a **candidate semantic map**, not certification of a missing original archive's schema. The publisher-linked [CICFlowMeter repository](https://github.com/ahlashkari/CICFlowMeter) is a current V4 source tree; its present contents do not prove the exact commit that produced CICIDS2017. Likewise, the corrected maintainer source is not automatically the exact archived extraction commit.

| Current feature group | Count | Candidate meaning and units | Comparison gate |
| --- | ---: | --- | --- |
| Flow Duration | 1 | Last packet time minus first packet time, microseconds. | Verify original field/unit; derive end times only from checked duration. |
| Total Fwd Packet / Total Bwd packets | 2 | Number of packets in each direction, count. | Check original aliases and direction assignment. |
| Total Length of Fwd/Bwd Packet | 2 | Sum of per-direction packet payload lengths, bytes. | Verify original aliases; avoid describing these as on-wire byte counts. |
| Fwd/Bwd Packet Length Max, Min, Mean, Std | 8 | Per-direction payload-length statistics, bytes. | Confirm names, zero/single-packet behavior and numeric validity. |
| Flow IAT Mean, Std, Max, Min | 4 | Statistics of successive packet-time differences, microseconds. | Check unavailable-statistic/NaN behavior. |
| Fwd IAT Total / Bwd IAT Total | 2 | Sum of per-direction packet gaps, microseconds. | Check direction and zero/single-packet behavior. |
| Active Mean, Std, Max, Min / Idle Mean, Std, Max, Min | 8 | Threshold-based active/idle duration statistics, microseconds. | Validate original distribution and extraction assumptions; names alone do not establish equivalent values. |

Primary source evidence: [publisher-linked BasicFlow.java](https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java) updates per-direction payload statistics, counts and gap statistics, and calculates timing from packet timestamps. The [corrected BasicFlow.java](https://raw.githubusercontent.com/GintsEngelen/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java) implements corresponding statistics. Rate conversions in both sources identify the microsecond time base. These definitions support candidate unit alignment, while changed flow construction necessarily changes observations and potentially their distributions.

The [correction documentation](https://intrusion-detection.distrinet-research.be/WTMC2021/tools_datasets.html) records changed FIN/RST flow termination, regenerated uploads and an idle-time fix. The [CNS2022 tools page](https://intrusion-detection.distrinet-research.be/CNS2022/Tools_Documentation.html) documents UTC/microsecond timestamp output and additional changes. Therefore paired results must continue to describe a population/data-version comparison, even if all 27 field definitions align.

## Timing and duplicated-header gates

The [publisher-linked DateFormatter.java](https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/DateFormatter.java) uses the host's default timezone; source output paths include 12-hour timestamp formats with differing AM/PM handling. **Do not infer the missing archive's exact format, timezone or AM/PM interpretation from the present code.** Inspect real values, compare them with official attack/capture windows, document any ambiguity, and normalize to UTC before shared boundaries. Original low-precision timestamps may also limit end-time reconstruction accuracy and require conservative boundary handling.

The publisher's [FlowFeature.java](https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/FlowFeature.java) explicitly annotates a removed duplicate of `Fwd Header Length` (historical positions 62 and 41). That is primary evidence of a historical duplicate-column issue, not proof of a particular not-yet-inspected archive. Read original headers positionally before constructing dictionaries. If duplicated names appear, record positions and compare values; do not silently accept parser-generated suffixes or collapse columns. This header is outside the current 27-feature policy, so an audited adapter may omit both copies after recording their presence.

Once acquired, remaining acceptance is: exact member/header/encoding inventory; explicit handling of duplicates; confirmed event-time and duration semantics; versioned raw-label mapping; a documented 27-feature intersection or justified revised intersection applied to both variants; then matched split-support and row-accounting audits. Original acquisition and adapter certification remain separate from the completed corrected-only baseline.
