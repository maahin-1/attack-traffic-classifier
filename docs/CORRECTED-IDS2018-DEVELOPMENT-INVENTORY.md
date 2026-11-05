# Corrected 2018 development-member inventory

The designated source is `Wednesday-14-02-2018.csv` from the CNS2022 regenerated archive. The inventory is development-only: it neither fits a model nor produces model scores. The member's acquisition must record a verified uncompressed CRC, byte count and SHA-256 before inspection; the inventory independently recomputes these checks and verifies stable inputs after parsing.

`attack_traffic.inspect_corrected2018.inspect_corrected_development` requires 91 unique columns, the 27 corrected feature names and source timestamp, label and attempted-category fields. It accounts for every CSV record as a data row, repeated header or malformed-width record. It separately counts missing, nonnumeric, nonfinite and negative feature values; a negative duration is marked invalid, while other negative measurements remain visible rather than silently excluded. It publishes no endpoint values or per-flow feature samples.

The proposed binary accounting applies only to documented development labels (`Benign`, the explicitly reviewed alias `BENIGN`, `FTP-BruteForce`, `SSH-BruteForce`, and the ` - Attempted` variants) and categories -1 through 6. Supplied benign labels or `Attempted Category != -1` map to benign, consistent with the correction authors' guidance. Unsupported categories and unknown/empty labels remain unresolved; mismatches between attempted-label strings and categories are counted. Source labels are preserved as supplied and are not treated as independently verified ground truth. This proposal is accounting for review, not transformed training data.

Coverage outputs include per-date and hourly counts, first/last parseable source rows, clock decreases in source order and per-label timestamp bounds. Timestamp parsing requires the regenerated release's microsecond timestamp representation, with the expected 14 February 2018 date checked separately. Reported timestamp semantics follow release documentation; timestamp ranges do not prove complete PCAP coverage or the exact historical producing extractor revision.

Three synthetic tests verify row/label reconciliation, attempted mapping, negative-duration and missing/nonfinite accounting, wrong dates, invalid timestamps, out-of-order clocks, acquisition CRC rejection, immutable destinations, the reviewed uppercase benign alias and derived-support mismatch rejection. The tests use project-local temporary storage to work under the Windows sandbox.

## Full-member findings

The completed inventory is `artifacts/corrected2018-development-inventory.json`. It independently verified **3,262,583,806 bytes**, CRC32 **af553b82**, and SHA-256 **4ceed4ba26973004e3a86ae0c57d6a4ddd9742f1b222f44209cd7c1c48618fdb** before and after the streaming inspection. No complete archive hash is claimed.

The file contains **5,898,350 data rows**, with no repeated headers, malformed-width rows, timestamp parse failures, missing/nonnumeric/nonfinite required features or negative required features. Its 91-column schema contains all 27 expected source names. This demonstrates coverage beyond the original publisher CSV's 1,048,575 rows, but changed reconstruction/labels mean it does not establish a record-for-record continuation or complete underlying PCAP coverage.

| Raw source label | Rows |
| --- | ---: |
| BENIGN | 5,610,799 |
| FTP-BruteForce - Attempted | 193,354 |
| SSH-BruteForce | 94,197 |

Attempted categories are -1 for 5,704,996 rows, category 1 for 193,324 and category 4 for 30. The initial strict development allowlist specified mixed-case `Benign`, so the actual uppercase `BENIGN` remains explicitly unresolved in the immutable first inventory. No case alias was silently introduced. The raw label/category counts permit an explicit reviewed alias decision without claiming that source labels are independently validated truth.

After reviewing those raw counts, uppercase `BENIGN` was explicitly accepted for future inventory runs. A separate artifact, `artifacts/corrected2018-development-reviewed-support.json`, derives **5,804,153 proposed benign** and **94,197 proposed attack** rows from the immutable first inventory's label/category support, without rescanning or replacing it. The artifact binds the input inventory and acquisition hashes, states the mapping update, verifies support reconciliation and confirms the 1,177 cross-date rows are benign using per-label timestamp bounds. No transformed training data or row exclusions are produced.

Timestamps are parseable throughout: 5,897,173 rows have the expected 14 February date; **1,177 BENIGN rows have 15 February dates**. These are reported as cross-date records, not automatically excluded or assumed invalid—UTC dates can spill beyond a file's nominal day. Source-order clocks decrease 2,558,012 times, so the file cannot be split chronologically by source row position.

Observed BENIGN timestamp bounds are 14 February 12:28:07.743746 through 15 February 00:47:34.715559. FTP-attempted bounds are 14 February 14:33:26.718731 through 18:01:21.502581; SSH bounds are 18:01:50.374537 through 19:32:29.744191. These release-provided UTC-format strings are more explicit than the original CSV clock strings, but no independent packet-level clock verification or completeness claim follows from the bounds. No model scores were computed and no training data were produced.
