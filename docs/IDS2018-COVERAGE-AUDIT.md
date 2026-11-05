# CSE-CIC-IDS2018 source coverage audit

The three locally acquired CSVs are complete copies of the recorded publisher objects: byte lengths and SHA-256 match their acquisition records before and after inspection. This establishes local integrity relative to those records, not authenticated publisher checksums or completeness of the underlying PCAP capture. No model was trained or scored during this audit. The full evidence is `artifacts/ids2018-coverage-audit.json`; `attack_traffic/coverage_ids2018.py` supplies a read-only, streaming audit and its synthetic test passes.

## Observed source boundaries and clock strings

| File date | CSV records after initial header | Repeated headers | First parseable source-row clock | Last parseable source-row clock | Source-order clock decreases |
| --- | ---: | ---: | --- | --- | ---: |
| 14 Feb | 1,048,575 | 0 | 08:31:01 | 10:53:28 | 289,765 |
| 15 Feb | 1,048,575 | 0 | 08:25:18 | 09:02:01 | 382,967 |
| 16 Feb | 1,048,575 | 1 | 08:27:23 | 10:36:33 | 268,941 |

The last record in a file is not its latest clock timestamp. The files are not chronologically ordered by their supplied strings, and the large decrease counts include legitimate ordering differences and possible clock ambiguity. No malformed-width records or timestamp-format parse failures were found. Five development-day benign rows contain parseable January 1970 dates, which should not be mistaken for valid capture coverage. The two evaluation files contain only their expected capture date. Per-label ranges and per-hour wall-clock counts are preserved in the JSON, without endpoints.

The [publisher schedule](https://www.unb.ca/cic/datasets/ids-2018.html) puts 14 February SSH at 14:01–15:31, but its CSV source strings span 02:01:21–03:32:30. Friday Hulk is scheduled 13:45–14:19, while source strings span 01:45:27–01:48:44. This is consistent with missing AM/PM information, but does not establish an exact conversion for every row. Do not interpret these strings as unambiguous 24-hour local time or UTC. Friday's Hulk source-label coverage is only 461,912 rows across that short raw-clock range; it does not demonstrate coverage of the whole scheduled attack period. Thursday GoldenEye source-label clocks span 09:27:42–10:02:59 versus scheduled 09:26–10:09, and Slowloris spans 11:00:12–11:42:01 versus scheduled 10:59–11:40. Schedules are context, not an independent flow-level ground truth or proof of missing traffic.

## What the common row count means

All three objects have exactly 1,048,576 CSV records when including the initial header. This equals Microsoft's documented [Excel worksheet row limit](https://support.microsoft.com/en-us/excel/excel-specifications-and-limits?app=wp). That is a concrete reason to suspect a row-capped export. It is not proof the publisher used Excel, that truncation occurred, or which traffic is missing. In particular, a source-order tail cannot be treated as the end of the capture because rows are not time-sorted.

No located primary publisher statement establishes the processing step that caused this count. The [correction researchers](https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html) document extraction and attack-label problems, but those findings do not by themselves prove the byte-complete files here are truncated. Confirming completeness needs publisher provenance, raw PCAP coverage or a separately verified regenerated release; any such release would also change extractor/label semantics and must be treated as a distinct experiment rather than silently replacing current data.

The existing robustness results therefore describe these exact publisher CSV objects, not guaranteed complete daily network traffic. This audit adds coverage limitations without changing their frozen models, thresholds, row rules or reported outcomes. The next experiment should explicitly test source/extractor sensitivity using documented compatible data and protected evaluation rather than optimize against an assumed complete-day clock split.
