# Experiment 008: packet probe preparation

This probe examines a previously selected, label-conflicting group from the consumed CIC-DDoS2019 assessment. It is forensic development work and cannot serve as an independent evaluation or prove dataset-wide label correctness. The user supplied the 03-11 PCAP archive, and the `_0137` segment has now been analyzed; see `docs/EXPERIMENT-008-PACKET-PROBE-RESULTS.md`.

## Candidate packet file

Request one publisher PCAP from `PCAPs/03-11` whose name contains `SAT-03-11-2018_0137` (the segment number is sometimes written `_137`). A [separate published packet-replay study](https://pmc.ncbi.nlm.nih.gov/articles/PMC13543096/) lists `_0137` among its high-speed SYN-flood segments. A [separate thesis](https://dspace.vut.cz/bitstreams/d5130b00-5dfa-4509-bdea-573e7a2f522b/download) lists segment `_137` from 14:14:54.298079 to 14:30:25.830426 UTC. These are third-party descriptions, not publisher metadata or a verified match to our local source row. Official PCAP names, file sizes, and hashes remain unverified because the publisher portal session expired.

The source CSV target has literal dataset-clock time `2018-11-03 11:29:17.786188` in `03-11/UDPLag.csv`, record 118419, label `Syn`, protocol 6, `SYN Flag Count` 0 and `ACK Flag Count` 1. Its flow identity details are stored locally in ignored `artifacts/experiment-008-packet-probe/targets.json` (SHA-256 `3e4581bb4bfd04f02430a8dfb974157fb6e4316468539747a7354170696f1713`); the selection and source archive hash are in the adjacent `protocol.json`. There are 220,687 rows with that same 27-feature digest and SYN label in the selected source-clock window. They are not necessarily the same underlying flow.

The thesis's reported UTC segment range and CSV clock suggest a possible three-hour offset, which would place this target within `_137`. This is a hypothesis for locating evidence, not an established timezone conversion. Verify it using multiple exact packet/flow matches, and report a failed match without silently shifting clocks or choosing another target.

## Inspection plan after acquisition

1. Record the exact publisher path, local filename, bytes, SHA-256, capture format/link type, and whether an independent publisher checksum is available. Do not execute the archive or modify its contents.
2. Identify packets matching the saved endpoint/protocol tuple in both directions and compare plausible timestamp offsets explicitly. Distinguish a matching tuple from a validated flow reconstruction; reused tuples, timeouts and direction rules can create ambiguity.
3. For unambiguous candidate packets, report the first observed packet's TCP flags and all flags observed over the documented flow interval. Compare both counts with the saved CSV fields and the [pinned upstream pre-fix and fix commit](https://github.com/ahlashkari/CICFlowMeter/commit/ed1d6bcbdefe161be51ac278f76be995f7121482). One example may support or contradict a particular hypothesis, but cannot establish the producer version or labels for the full archive.
4. Keep source and output fingerprints, parser version, clock assumptions, coverage and unmatched cases. `scripts/packet_probe_008.py` supports an uncompressed classic PCAP with Ethernet/VLAN or raw IPv4 link type. It streams matching tuples without assuming a CSV-to-PCAP clock offset, and rejects PCAPNG, compressed inputs, and other link types. An independently implemented decoder supplied the 20-tuple cross-check. The two decoders passed ten focused synthetic checks; their actual `_0137` results are in the results note. Tuple matches do not by themselves establish reconstructed flows. The current environment has no `tshark`, `capinfos`, Java, Scapy, or dpkt on PATH.

The user supplied the archive in ignored `data/cicddos2019/pcaps/`; only the target `_0137` member was extracted. The archive's internal CRC and local hashes were verified, but no publisher checksum was available to establish independent provenance.
