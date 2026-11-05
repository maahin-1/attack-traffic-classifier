# Experiment 008: packet and CSV flag comparison

## Scope

The user supplied `PCAP-03-11.zip` (2,000,948,331 bytes, local SHA-256 `cdc8935296cab7a2354d4fd32939f7d5e6c592371e5fb89d6a3094cc05dc38c5`). The requested archive member `SAT-03-11-2018_0137` was extracted without extracting the other members. It is a little-endian classic PCAP, 200,000,032 bytes, SHA-256 `e8d76130a6e5014177a9260345495fc48ac667fc31f92782748621cac69c43bc`. Reading the ZIP member completed its internal CRC check; no independent publisher checksum was available here, so that check is not publisher authentication.

The probe examines selected records from the already consumed CIC-DDoS2019 assessment. It is a post-assessment forensic analysis, not model evaluation or a random dataset sample. The initial target is source member `03-11/UDPLag.csv`, CSV record 118419, label `Syn`, dataset-clock time `2018-11-03 11:29:17.786188`, flow duration 1 microsecond, two forward packets, zero backward packets, `SYN Flag Count` 0, and `ACK Flag Count` 1. Its endpoint tuple is kept in the ignored local target artifact rather than repeated here.

## Initial packet match

The streaming scanner read 2,465,197 packet records in the supplied segment and found exactly two packets matching that TCP endpoint tuple, both in the CSV forward direction. Their PCAP UTC timestamps are `2018-11-03 14:29:17.786188` and `14:29:17.786189`; both raw TCP flags decode as **SYN only** (`0x02`). Their timestamps are exactly three hours ahead of the CSV's literal clock and one microsecond apart, matching the CSV packet count, direction and duration. This is strong evidence for a corresponding packet pair in this segment, although a 5-tuple match and time agreement alone do not prove how the historical producer assembled every flow.

The source CSV reports SYN count **0** and ACK count **1** for this row. The two matched packet headers contain SYN on both packets and ACK on neither. If the historical flow contained exactly these two packets and the CSV headers have their literal meaning, neither simple first-packet-only flag counting (expected SYN 1, ACK 0) nor full two-packet counting (expected SYN 2, ACK 0) explains the observed CSV fields. Other explanations, including flow reconstruction or column serialization/processing differences, remain possible. This observation does **not** identify the producer version or prove the label malicious; a SYN packet can also be part of normal connection establishment.

## Focused cross-check

Before reading packet results for the wider check, the runner fixed a convenience selection: the first 20 distinct TCP tuples in CSV record order with label `Syn`, the same 27-feature digest as the initial target, and source-clock times between 11:29:00 and 11:30:26. These 20 rows come from one feature group and a short interval, so they are not independent representative samples of the dataset.

An independently implemented Ethernet/IPv4/TCP decoder scanned the same 2,465,197-packet segment once. For **20 of 20 selected tuples**, it found exactly two forward packets with raw TCP flags `0x02` (SYN only), at the CSV timestamp plus three hours and plus three hours and one microsecond respectively. All 20 selected CSV records have `SYN Flag Count` 0, `ACK Flag Count` 1, and `URG Flag Count` 0. The narrowly observed timestamp relationship is consistent with a three-hour offset for these records; it does not establish a timezone rule for the whole dataset.

The published pre-fix source calls its flag counter for the first packet but comments out the call for subsequent packets; [the 15 October 2019 change](https://github.com/ahlashkari/CICFlowMeter/commit/ed1d6bcbdefe161be51ac278f76be995f7121482) enables the subsequent-packet call. The [correction researchers](https://intrusion-detection.distrinet-research.be/WTMC2021/extended_doc.html) document the first-packet counting issue in CICIDS2017 and say other datasets may be affected. The exact CIC-DDoS2019 producer build and any intervening CSV processing are still unverified. The mismatch observed here requires a broader explanation than assuming first-packet-only counting alone, conditional on the matched pair and field interpretation above.

## Exploratory check across different feature groups

After the initial result, a second, explicitly post-hoc convenience sample selected the first 20 distinct 27-feature groups per `BENIGN` and `Syn` label from the same CSV member and source-clock interval 11:15–11:30. Selection required TCP, two forward and zero backward packets, 0–1,000 microseconds duration, and distinct tuples; the previously observed +3-hour hypothesis was then used to locate packets in each CSV duration window. No flag value was used to select the examples. This is still one file and one short capture period, not a random, independent dataset sample.

All 20 `Syn` candidates and 18 of 20 `BENIGN` candidates had exactly two forward tuple-matching packets at the expected interval endpoints. The two remaining benign candidates each had three matching packets in their windows and were excluded from the flag comparison. All 18 retained benign tuples also had other packets outside their individual windows (675 such packets in total), so historical flow segmentation remains uncertain even for those time-aligned examples. The 20 retained SYN tuples had no other matching packets within this segment.

For the 38 retained examples, an exploratory comparison of CSV flag **presence** against the first time-aligned packet produced these associations:

| CSV field | Rows where CSV field is positive | First-packet flag with identical presence over these 38 examples |
| --- | ---: | --- |
| `ACK Flag Count` | 20 | SYN |
| `URG Flag Count` | 18 | ACK |
| `RST Flag Count` | 12 | PSH |
| `CWE Flag Count` | 4 | FIN |

The observed first-packet combinations were SYN (20), PSH+ACK (12), FIN+ACK (4), and ACK alone (2). No first matched packet had RST, URG, ECE, or CWR, so this sample cannot identify a complete flag mapping. The associations suggest a possible field-order or serialization issue, but they do not prove one or authorize relabeling columns. In one [historical upstream writer method](https://github.com/ahlashkari/CICFlowMeter/blob/99dc82768a0ebbf2be63a506b185113f52ab1edf/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java), flag counts are iterated through a `HashMap`; the inspected [standard flow export paths](https://github.com/ahlashkari/CICFlowMeter/blob/99dc82768a0ebbf2be63a506b185113f52ab1edf/src/main/java/cic/cs/unb/ca/jnetpcap/FlowGenerator.java) instead call the explicitly ordered `dumpFlowBasedFeaturesEx` method. Therefore the mere existence of the `HashMap` path is not evidence it produced this CSV. The actual producer path, version, and any later processing are unknown.

The diverse sample is `artifacts/experiment-008-packet-diverse/report.json` (SHA-256 `a43100338af4c152bb4435815a0d58983ffd4e1eb6bf5bd02368fd6b501920c4`). The post-hoc correlation audit is `artifacts/experiment-008-flag-hypotheses/report.json` (SHA-256 `151b6b7af542041cfd52c2a8efca7e46100ee9d175db6a4d0d9883b12cb12db0`); its protocol was saved before the correlation calculation. Both retain the two ambiguous candidates or their exclusion explicitly. The focused flag-comparison and correlation checks passed. Do not apply these associations as a production correction without independent examples covering all flags and a verified producer/serialization path.

## Artifacts and verification

- Single-tuple report: `artifacts/experiment-008-pcap-inspection/report.json`, SHA-256 `70a3a6724d85563068e1a580c5a404e67ed10eee23fe0fed2e3264269c5bc3c3`.
- Twenty-tuple report: `artifacts/experiment-008-packet-sample/report.json`, SHA-256 `7a5f1cef6efb214a4571da859a6a3c346647a2e0c3410137c7d5d943a0fd3abc`. Its pre-scan selection protocol SHA-256 is `eec44b5df31e21b0d7685a01ebb9021df8c23c72ebe8a3143e1edca189c87a09`.
- The two packet decoders use separate implementations. Ten focused synthetic checks covering flags, directions, capture byte order, VLANs, unsupported formats, and truncation passed. Source PCAP and CSV archive hashes were verified before and after the checks.
- The first probe's target and parser protocols are in `artifacts/experiment-008-packet-probe/` and `artifacts/experiment-008-pcap-inspection/`. Endpoint tuple values remain in the ignored local target file; report examples omit endpoint addresses.

Do not treat the raw 2019 flag-count headers as validated model features. Next, trace the historical CSV-writing and labeling pipeline, and compare additional predeclared groups or captures before deciding whether a versioned mapping can be justified. Any subsequent modeling is development work and requires a new independent capture for final evaluation.
