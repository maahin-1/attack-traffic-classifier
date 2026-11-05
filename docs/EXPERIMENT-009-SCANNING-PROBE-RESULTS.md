# TON_IoT scanning development probe results

## Sources and scope

The user-supplied `normal_scanning.zip` is 4,838,365,508 bytes and contains all six scanning captures, rather than only the requested `normal_scanning6.pcap`. The two members fully inspected below are **development-only**. The event CSV and both capture members are consumed for development; none is an untouched final holdout. The ZIP's other members were not fully scanned; only their first packet headers were examined in the separate [metadata plan](EXPERIMENT-009-SCANNING-METADATA-PLAN.md).

Both full member reads passed their ZIP CRC checks; the CSV and ZIP archive were SHA-256 checked before and after each probe. ZIP CRC and local hashes establish internal consistency, not publisher-authenticated provenance. Capture time ranges below are based on packet timestamps interpreted as Unix epoch seconds in UTC; CSV timestamps are interpreted the same way. This convention is a working assumption, not independently synchronized clock verification.

The entire `GroundTruth_Network_1.csv` contains **1,000,000 records**, each with the expected seven fields. All have the source type `scanning`; 994,309 use TCP, 4,750 UDP, and 941 ICMP. The ICMP rows are valid source rows but unsupported by this TCP/UDP tuple probe. Their timestamps, along with the rest of the CSV, range from **2019-04-23 12:10:10** to **13:24:17 UTC** under that interpretation. These are event records, not a verified complete set of flows or benign traffic. No raw endpoints are included in the generated reports.

## Requested scanning6 member

The 479,811,584-byte `normal_scanning6.pcap` is pcapng using Linux cooked link type 113. It contains 3,259,683 timestamped packet blocks spanning **2019-04-24 06:11:25–09:56:37 UTC** under the stated interpretation. There are 2,994,304 decodable IPv4 TCP packets, 32,105 IPv4 UDP packets and 233,274 other/unsupported packets. The full CSV time range does not overlap this range. Consequently **no candidate event keys were selected and no tuple match comparison was possible**; zero matches is not an observed failure rate or proof of a timezone mapping. Other offsets were not searched.

## Scanning1 follow-up

A subsequent header-only inventory found that `normal_scanning1.pcap` begins at **2019-04-23 12:10:09 UTC**, one second before the earliest CSV event, so it was selected post-hoc for a separately predeclared [development probe](EXPERIMENT-009-SCANNING1-PROBE-PLAN.md). The full 617,628,321-byte capture has 625,737 packets and spans **12:10:09–13:15:02 UTC** under the same interpretation. Its ZIP CRC passed.

Of the CSV's TCP/UDP rows, 74,701 fall in that packet time range. The first **50,000 distinct eligible event keys** in CSV order were selected; a key includes the event second, protocol and directional IPv4 addresses and ports. In the full capture:

| Comparison | Selected event keys |
| --- | ---: |
| Same-second directional tuple present | 25,535 |
| Same-second reverse-direction tuple present | 6,552 |
| Either direction present | 27,055 (54.11%) |
| Neither direction present | 22,945 (45.89%) |

The two directional groups overlap: 5,032 event keys match both directions, so their counts must not be added. A direct-match key can correspond to multiple packets; there were 27,673 direct-matching packets. These are matches to **a packet**, not reconstructed flow matches. Sample selection was deterministic but post-hoc and not random; results are not general accuracy estimates, and no attempted offset search or adjudication of unmatched events was performed. Captured-packet absence can reflect several causes, including timing, source-event definitions, packet visibility or unsupported protocols.

The matching scan only checks TCP/UDP IPv4, Linux cooked v1 and Ethernet; noninitial IPv4 fragments and other traffic are omitted from tuple decoding. Capture completeness and cross-file overlap are unproven. The CSV contains scanning events only, so it cannot establish a complete benign-vs-attack training or evaluation population. Event records do not provide verified flow boundaries, durations or a robust benign-label policy. Do not treat unmatched flows as benign by default.

## Verification and next step

Six focused tests passed for the packet readers, Linux cooked UDP decoding, timestamps, malformed blocks, noninitial fragments and header-only inspection. The first scanning6 report incorrectly called 941 ICMP rows invalid; the versioned second run records them as unsupported by this TCP/UDP comparison and records zero invalid rows. Reports: [scanning6 v2](../artifacts/experiment-009-scanning6-probe-v2/report.json), [scanning1](../artifacts/experiment-009-scanning1-probe/report.json), and [first-header inventory](../artifacts/experiment-009-scanning-starts.json). Their SHA-256 values are `e2a572f1fc8a808ae7c51ccca9db7bb5443f8d2925cf87d645b2c5306e866d35`, `bcd3ca518be20eb65d80439c97b94cbf6cfe249636377600d082680f2d51feae`, and `5f960433a1c666e0d14f34079b17569b998f3a90b44cf3edc133adea94d9fcc6`, respectively.

Next, investigate source-event semantics and the causes of unmatched selected keys using a separately declared, privacy-preserving development diagnostic. In parallel, identify independent benign capture coverage and a pinned packet-to-flow extractor. Preserve separate capture sessions for calibration and final assessment; do not use these consumed development members as the final holdout. No model was trained, evaluated or changed, and disputed flag fields remain excluded.

The subsequent [timestamp diagnostic](EXPERIMENT-009-UNMATCHED-DIAGNOSTIC-RESULTS.md) found same-tuple packets in the prior second for all previously unmatched selected keys; subsecond evidence is consistent with rounding but does not establish source conversion or flow identity.
