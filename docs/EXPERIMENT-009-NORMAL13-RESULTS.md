# TON_IoT normal13 development inventory

The user supplied `normal_13.pcap` (1,065,001,940 bytes), which was listed as 0.99 GB under the publisher's `normal_pcaps` folder. Local SHA-256: `bf6a9d2adc0da1436df48c7bbac3c51858c19eb290b792698cd5ae42a4434b76`. The file's hash was checked before, during and after both scans; no independent publisher checksum was available. This is a **development-only** capture and is not a reserved final assessment.

## Time coverage

The file uses pcapng, Linux cooked capture v1 (link type 113), and microsecond timestamp resolution. It contains **1,918,446 packet blocks**. Interpreting recorded epoch timestamps as UTC, its earliest and latest packets are 2019-04-03 06:47:20 and 2019-04-04 07:48:09. Packets were observed in the hours 06:00–08:59 on April 3 and 06:00–07:59 on April 4; this is not proof of continuous capture between those times.

The overall range does not overlap the previously examined scanning1 capture or `GroundTruth_Network_1.csv` (both 23 April under the same interpretation). This is useful separation in recorded dates, but it does not independently establish clock accuracy, capture/session independence, absence of duplicated activity or benign labels.

## Decoder coverage

The existing TCP/UDP IPv4 decoder identified **258,095 TCP** and **12,787 UDP** packets. The remaining **1,647,564** were outside that decoder. A separately planned [header classification](EXPERIMENT-009-NORMAL13-PROTOCOL-PLAN.md) reproduced all packet counts:

| Observed cooked-link classification | Packet blocks |
| --- | ---: |
| Protocol field `0x0003` | 1,599,685 |
| IPv4 (`0x0800`) | 298,552 |
| ARP (`0x0806`) | 12,566 |
| IPv6 (`0x86dd`) | 7,643 |

The current decoder does not interpret link-layer protocol value `0x0003`. A later convenience check of the first 5,000 such frames found that their first payload nibble was zero, with none matching two simple tested LLC prefixes or a basic Ethernet-type check. These limited heuristics do not establish their actual encapsulation or usable model coverage; do not infer that those frames are benign or that they contain no IP traffic. Within observed IPv4 headers, protocol counts were 258,095 TCP, 12,789 UDP, 26,928 ICMP and 740 IGMP. Two UDP packets were noninitial fragments and thus were omitted by the existing tuple decoder. Those are packet counts, not flow counts.

## Label and evaluation limits

The source folder name suggests normal traffic, but the supplied README and this inventory do not independently establish that all packets are benign or that event logs are complete for the capture. The only ground-truth CSV examined so far contains scanning events from a different date; its lack of overlap does not establish this capture is attack-free. No packet or flow was automatically assigned a benign label, and no model was trained, scored, calibrated or changed. A genuinely independent final holdout is still unselected.

Before using the file for training or FPR measurement, investigate `0x0003` encapsulation on bounded development examples, validate a pinned packet-to-flow extractor, establish the source's capture and event-label coverage, and document session grouping and any ambiguous packets. Compare candidate extraction coverage and both retained and excluded traffic, rather than silently assuming all traffic is represented. Keep disputed flag features excluded.

The subsequent [cooked-header investigation](EXPERIMENT-009-NORMAL13-SLL-RESULTS.md) established that the ambiguous frames all have outgoing/Ethernet cooked-header metadata but did not establish their encapsulation. The [development label policy](EXPERIMENT-009-DEVELOPMENT-LABEL-POLICY.md) keeps their and the capture's benign status unverified.

## Evidence

The [initial inventory](../artifacts/experiment-009-normal13-inventory/report.json) has SHA-256 `8aad91865e291e215027e6bed20d34d3fa3c366503662c81a21d24c0f46207cf`; the [protocol diagnostic](../artifacts/experiment-009-normal13-protocol/report.json) has SHA-256 `5c1e843f3ed6daeed776ab4f632d9d8ff7543f14e7e26e983a8112f4bce86717`. Three focused synthetic tests passed for inventory, decoder behavior and truncated headers. Both reports preserve aggregate counts only; raw addresses, ports and payloads are not exported.
