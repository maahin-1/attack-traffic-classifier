# Experiment 008: stratified TCP-flag investigation

## Selection and matching

After inspecting earlier results, the exploratory [plan](EXPERIMENT-008-FLAG-STRATIFIED-PLAN.md) selected up to 20 distinct 27-feature groups per observed eight-column CSV flag pattern from `03-11/UDPLag.csv`, using TCP rows with two forward packets, no backward packets, durations 1–1,000 microseconds, and source-clock times 11:15–11:30. The sample is post-hoc and stratified on CSV flag patterns, not random or independent of the earlier investigation. The actual selection was 61 rows across six patterns.

The previously observed +3-hour offset hypothesis was used to find each tuple and the two endpoints of its CSV duration window in the supplied `_0137` packet segment. **55 of 61** candidates had exactly two forward tuple-matching packets at the expected endpoints; six were unmatched or ambiguous and were excluded from the flag comparison. **35 of the 55** matched tuples had other packets outside their selected windows, so exact historical flow segmentation remains uncertain. The 55 first-packet flag patterns comprised 20 SYN, 19 PSH+ACK, seven FIN+ACK, seven ACK, one RST+ACK, and one FIN+PSH+ACK. No first matched packet carried URG, ECE, or CWR.

## Observed agreements, not a correction

Each comparison below treats a CSV count as positive or zero and compares it to the indicated bit in the first time-aligned packet. The percentages are not estimates of general mapping reliability.

| CSV field | Positive examples | First-packet bit with matching presence | Agreements |
| --- | ---: | --- | ---: |
| `ACK Flag Count` | 20 | SYN | 55 / 55 |
| `URG Flag Count` | 35 | ACK | 55 / 55 |
| `RST Flag Count` | 20 | PSH | 55 / 55 |
| `CWE Flag Count` | 8 | FIN | 55 / 55 |
| `SYN Flag Count` | 1 | RST | 55 / 55 |

The last association has only **one positive RST example**. `FIN`, `PSH`, and `ECE` CSV fields are zero throughout the matched sample, while the URG, ECE, and CWR packet bits are also absent; these values cannot identify a complete mapping. The sample overlaps the earlier investigation and some endpoint tuples have other packets outside their matching windows. The observed associations are hypotheses, not a validated dataset-wide remapping or an adjudication of source labels.

## Historical writer evidence

An independent source review identified two historical writer methods. At upstream commit [`99dc8276`](https://github.com/ahlashkari/CICFlowMeter/blob/99dc82768a0ebbf2be63a506b185113f52ab1edf/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java), the standard extended writer emits named flag counts explicitly; the inspected [GUI and flow-generator export path](https://github.com/ahlashkari/CICFlowMeter/blob/99dc82768a0ebbf2be63a506b185113f52ab1edf/src/main/java/cic/cs/unb/ca/jnetpcap/FlowGenerator.java) calls that extended writer. A different method iterates a `HashMap`, but its use for these published CSVs has not been shown. The [historical packet reader](https://github.com/ahlashkari/CICFlowMeter/blob/99dc82768a0ebbf2be63a506b185113f52ab1edf/src/main/java/cic/cs/unb/ca/jnetpcap/PacketReader.java) passes named TCP flag accessors to named packet fields. The producer version, runtime, writer path, header generation, and later CSV processing used for this particular archive remain unknown; the `HashMap` path is not an established cause.

## Capture coverage and next step

The whole `_0137` segment contains 2,454,268 parseable IPv4 TCP packets. Their TCP flag bits include SYN 1,770,814, ACK 684,542, RST 653,610, PSH 10,660, and FIN 1,846. **URG, ECE, and CWR occur zero times** among those parseable packets, so this segment cannot validate associations for those first-packet bits. This is a packet-level inventory, not a count of CSV flows or labels; noninitial fragments, truncated headers, and non-IPv4/TCP packets are excluded by the decoder.

The [additional segment plan](EXPERIMENT-008-ADDITIONAL-PCAP-PLAN.md) selected three further members from the supplied archive after the initial inspection. Their complete packets included 120,909, 2,616,185, and 185,434 parseable IPv4 TCP packets in `_0`, `_0138`, and `_0145`, respectively. URG did not occur in these members. Two packets in `_0145` carried both ECE and CWR along with SYN (mask 194); the first was at 2018-11-03 19:46:50.527385 UTC. The scan did not attempt to match these packets to CSV rows, so it cannot establish how either flag was exported. These convenience selections cannot establish flag frequency or absence elsewhere in the archive.

All three ZIP members were read fully and passed their internal CRC checks. The last member ends in a truncated packet record: 18 of the expected 72 packet bytes were present. This incomplete record was excluded from packet and flag counts. A ZIP CRC verifies the supplied member against its ZIP metadata, not against an independent publisher checksum. The initial inventory failed on the truncated record; the versioned rerun records the truncation and completed, with synthetic tests for both complete and truncated records.

The next investigation is to identify whether the two ECE/CWR packets correspond to source CSV flows, recording tuple, timestamp, capture coverage, segmentation, and any unmatched cases. The earlier +3-hour alignment is a hypothesis that must be checked in this separate time window. Preserve the consumed-assessment status and retain the current feature exclusion until broader packet evidence and the actual producer/processing path are established. A new, independently captured holdout remains necessary for any later model claim.

Artifacts: `artifacts/experiment-008-packet-stratified/report.json` (SHA-256 `ce42ca108ee05e3888ba2020d0e2d536c54360422cc36d84316d0a57421c88c3`), its pre-packet-scan `protocol.json` (SHA-256 `38b344e9deea3ec39fa835e1df598810ce4a8f84bed8734b6855140fdbd80485`), `artifacts/experiment-008-pcap-flag-inventory/report.json`, and `artifacts/experiment-008-pcap-multi-inventory-v2/report.json` (SHA-256 `7f05f9ae1fb57b22e30e05fad6f458adda1fb243f7e1dd50e45dcc0d777fedbf`). Input and implementation fingerprints were checked before and after their respective scans. Focused synthetic agreement and inventory tests passed; existing packet-decoder tests cover parsing. No model was trained and no CSV fields were corrected in this investigation.
