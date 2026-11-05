# Original adapter: capture-date chronology and feature contract

Decision research checked 2 November 2026. **Day-chronological comparison is defensible under an explicit capture-date policy; exact original UTC event times are not recovered.** Implementing this policy is a prerequisite to calling the paired run chronologically controlled. Relabeling ambiguous source times as precise UTC instants would not satisfy it.

## Snapshot and observed schema

Local original acquisition evidence records `GeneratedLabelledFlows.zip`, 283,876,488 bytes, SHA-256 `7bdbef286f8893f31c6db12105fa097fa5c2dcc6733179037a08129d150ea27a`, matching supplied publisher MD5 `5ca3f8f69e3514950681615824149973`, with all ZIP CRCs checked. The snapshot contains eight CSVs and a directory entry. The header inspection shows 85 columns, including two whitespace-normalized `Fwd Header Length` columns in each CSV.

The first inspected timestamp values illustrate varying formatting and lost AM/PM context:

| Member | Observed first timestamp |
| --- | --- |
| Monday | `03/07/2017 08:55:58` |
| Tuesday | `4/7/2017 8:54` |
| Wednesday | `5/7/2017 8:42` |
| Thursday morning | `6/7/2017 8:59` |
| Thursday afternoon | `6/7/2017 1:00` |
| Friday morning | `7/7/2017 8:59` |
| Friday afternoon DDoS | `7/7/2017 3:30` |
| Friday afternoon PortScan | `7/7/2017 1:00` |

These are header/first-record observations from `data/original/schema-inspection.json`, not a complete timestamp validity inventory. A complete adapter must validate every selected date and duration, with aggregate checks on the full source where available. Raw endpoint identifiers are neither needed nor reproduced here.

## What primary evidence supports

The [publisher schedule](https://www.unb.ca/cic/datasets/ids-2017.html) identifies capture days 3–7 July 2017, Monday benign-only, with attacks on subsequent days. Those calendar dates support the day/month/year interpretation of this particular snapshot. The schedule describes daytime activity; it does not establish an exact per-row clock reconstruction.

The correction authors' [labelling source](https://raw.githubusercontent.com/GintsEngelen/WTMC2021-Code/main/labelling_CSV_flows.py) explains host-timezone conversion during flow extraction. Its configurable host offset is not a universal offset for the original CSV release. The publisher-linked [DateFormatter source](https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/DateFormatter.java) uses the host timezone, and [BasicFlow source](https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java) contains 12-hour output paths. Neither present source tree proves the exact producer commit or original processing timezone.

The [CNS2022 tools documentation](https://intrusion-detection.distrinet-research.be/CNS2022/Tools_Documentation.html) explicitly documents UTC output with microsecond precision; the downloaded corrected inventory matches that format. The roughly three-hour difference between sampled original morning values and corrected UTC values is consistent with a local-clock interpretation, but reconstructed populations are not verified matched rows. **Do not use that numerical resemblance to assert exact UTC conversion.**

There is no independent epoch timestamp in the inspected original schema. The publisher's [BasicPacketInfo source](https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicPacketInfo.java) builds Flow ID from endpoints, ports and protocol, not event time. CSV record position is a stable local reference, not evidence of AM/PM or elapsed time. Do not reconstruct clocks from identifiers or align original/corrected rows by position.

## Recommended temporal policy

1. Declare `temporal_basis=capture_date`, `original_clock_status=ambiguous_12h_no_offset`, date format `day/month/year`, and source precision (minute or second) per record. Preserve the original timestamp locally as metadata. Parse the date independently; require it to match the known capture day of its archive member. Unexpected dates or unparseable values fail/exclude visibly; never inherit a date from a label.
2. Use the same **capture-day partitions** for both variants: train 3–4 July, validation 5 July, test 6–7 July. For corrected flows derive capture day from the documented UTC timestamp and validate against its daily member. Its observed starts remain within the same calendar capture day. Describe the shared controls as day boundaries, not identical recovered UTC event cutoffs.
3. For original hours 1–12 without AM/PM, retain both AM and PM possibilities. Treat missing seconds as uncertain rather than zero evidence: conservatively widen by up to 60 seconds for minute fields and 1 second for second fields when the formatting/rounding operation is unverified. Use each candidate start interval plus verified nonnegative finite Flow Duration microseconds to bound possible flow end times.
4. Quarantine a row if **any plausible interval crosses a train/validation or validation/test day boundary**, or if the day assignment itself is uncertain. A minute-level `11:59` near a possible midnight and a nonzero duration is an example requiring care. Do not rely solely on the documented 120-second nominal timeout: validate actual durations and handle anomalous values. An interval wholly within one partition is safe for that partition even if its exact instant remains unknown.
5. Sort on capture date plus a deterministic local reference. For duplicate groups across days, retain the earliest eligible day and quarantine later days. Within a day, missing AM/PM prevents claiming true earliest-event retention: document stable file/record tie-breaking as an approximation, and quarantine or separately disclose conflicting-label duplicate groups. Do not label that order as measured event chronology.
6. Persist `capture_date`, interval/precision policy, selected partition and timing-quality status in audit evidence. If a legacy pipeline needs an ISO sort key, a date surrogate must be named and tagged as a **partition key**, not exported as a measured `event_start` or used for daily-duration/capacity claims. Reports and Parquet metadata must preserve that distinction.

This preserves the PRD's earlier-day training/later-day evaluation goal while limiting its resolution honestly. It changes the TRD's exact-event timing representation and within-day duplicate-order assumption; record the deviation in the manifest/report and test it. No intraday split, latency estimate, flow-to-flow temporal matching, verified label-only cohort or measured daily alert capacity is established by this adapter.

## Shared 27-feature policy

The inspected original header supports all 27 corrected-only numeric statistics. Four source-name aliases are needed after whitespace trimming:

| Original field | Corrected field | Canonical feature | Unit |
| --- | --- | --- | --- |
| Total Fwd Packets | Total Fwd Packet | total_fwd_packets | count |
| Total Backward Packets | Total Bwd packets | total_bwd_packets | count |
| Total Length of Fwd Packets | Total Length of Fwd Packet | total_fwd_bytes | payload bytes |
| Total Length of Bwd Packets | Total Length of Bwd Packet | total_bwd_bytes | payload bytes |

The other 23 fields have matching trimmed names: Flow Duration (1); forward/backward Packet Length Max/Min/Mean/Std (8); Flow IAT Mean/Std/Max/Min (4); Fwd/Bwd IAT Total (2); Active Mean/Std/Max/Min (4); Idle Mean/Std/Max/Min (4).

The two maintainers' BasicFlow implementations ([publisher-linked](https://raw.githubusercontent.com/ahlashkari/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java), [correction maintainer](https://raw.githubusercontent.com/GintsEngelen/CICFlowMeter/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java)) support packet counts, directional payload-length statistics in bytes, and duration/gap/active/idle statistics in microseconds. Population changes and changed direction/termination logic mean corresponding definitions do **not** imply equal observations. Record this as an alias/unit-level common policy, with extraction-version effects retained in the experiment.

The [correction authors' extended documentation](https://intrusion-detection.distrinet-research.be/WTMC2021/extended_doc.html) confirms the original duplicate header and distinguishes an absolute-time Active/Idle implementation bug in later regeneration from the originally released CICIDS2017 data. Do not claim the original release's Active/Idle features necessarily contain absolute timestamps; inspect values and lineage. The [upload history](https://intrusion-detection.distrinet-research.be/WTMC2021/tools_datasets.html) records subsequent fixes and regenerated populations. Both duplicate Fwd Header Length columns are outside these 27 features: account for their positions and omit them explicitly rather than silently collapsing them.

## Proceed / block criteria

Proceed with a **capture-day population comparison** only when date/member consistency, conservative possible-boundary quarantine, duplicate-date ordering, matching numeric feature policy, complete row accounting, and retained binary support are tested and recorded. Report original intraday time as ambiguous. Preserve raw labels and use a separately versioned alias map for original label spellings/encoding; do not infer labels from calendar windows.

Block a run that requires precise original UTC event times, exact intraday chronological ordering, or label-only matched-flow effects. Also block if the adapter cannot represent timing uncertainty without mislabeling surrogate dates as real events, or cannot rule out a row spanning partition boundaries under its declared candidate intervals. Resolving those claims requires independently verified source timing evidence or a different experiment; the day-level comparison does not resolve them.
