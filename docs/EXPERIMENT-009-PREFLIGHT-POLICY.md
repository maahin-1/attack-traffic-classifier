# Experiment 009: conservative synthetic PCAP preflight policy

This standalone research check does not invoke an extractor or authorize model
use. It accepts only complete, nonempty classic PCAP captures with Ethernet
(DLT 1) or Linux cooked v1 (DLT 113) frames containing IPv4 TCP/UDP packets.
It permits equal timestamps, but rejects any timestamp decrease in file order
across the entire capture. It rejects any IPv4 fragment (including a first
fragment with the more-fragments bit), unsupported link/network/transport
protocols, VLAN tags, IPv6, pcapng, incomplete or malformed headers and
records, captured frames shorter than original wire length, and IP or transport
length inconsistencies. An individual record above 16 MiB is out of scope.
There is no sorting, reassembly, repair, sampling, or silent row skipping.

The check produces only an acceptance/rejection reason and aggregate packet
count, without addresses, payloads or labels. It is not a guarantee of correct
checksums, semantic validity, capture provenance or file immutability between
preflight and later extraction. A future integration would have to bind the
checked bytes to the extractor input and define supported traffic coverage.
In particular the normal_13 cooked protocol 0x0003 is outside this policy;
rejecting it does not characterize its contents or label.

Test both supported link types, exact/equal time and inversions, first and
later fragments, truncation at multiple structural layers, unsupported input,
empty input, and TCP/UDP length anomalies using only generated fixtures. The
sample-standard-deviation issue remains a separate feature-contract decision.
