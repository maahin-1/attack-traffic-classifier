# Experiment 009: second extractor synthetic-only plan

Candidate: `Shahid-Wani/pycicflowmeter` at commit
`4432a32e05491c110f78fe80a59ab733b145d2cb`, downloaded source archive SHA-256
`db4a1b578fb159503db963bcba48300d0ad42fc9237d8cf1c62dbf05e3455850`.
This is a third-party implementation, not original Java CICFlowMeter. Run its
offline CLI directly from verified extracted source with the existing isolated
Python and Scapy environment. No live capture, real PCAP, fitting or scoring.

Before execution, generate deterministic classic-PCAP synthetic cases:

* the earlier equivalent Ethernet and Linux cooked TCP fixtures, each with
  2 forward, 1 reverse packets, TCP protocol 6 and 1,000,000 microseconds duration;
* a single Ethernet UDP packet, 1 forward and 0 backward, protocol 17 and
  duration zero;
* two Ethernet UDP packets with the same ports in reverse directions, 2 seconds
  apart, 1 packet each way, duration and whole-flow gap 2,000,000 microseconds;
* two independent UDP five-tuples, one packet each, expected as two flows.

Use RFC documentation addresses and fixed timestamps. Check source/destination
and ports, packet counts, duration and applicable gaps. Check all 27 canonical
fields by the project's explicit aliases, accounting for documented spelling
differences, and report missing/placeholder values separately. Compare values
between equivalent link types, but don't assume different packet-size
conventions are automatically wrong. These cases do not validate all feature
definitions, timeout behavior, capture coverage, labels, historical producer
version, or model compatibility. Save raw results, source identity, fixture
and runner hashes, command output, and dependency list. No tuning from results.
