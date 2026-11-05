# Experiment 009: offline extractor feasibility results

## Decision

Do not use Python `cicflowmeter==0.4.0` to extract model features from TON_IoT
captures based on this spike. The command-line path fails locally, and the
separate offline API produces incorrect packet counts on a controlled example.
No real capture was processed and the frozen model, feature exclusion, and
thresholds were not changed.

## Synthetic fixture

Two PCAPs contain the same three TCP packets: two forward, one reverse, with
one second from first to last packet. One has Ethernet headers and the other
Linux cooked v1 headers. IP and TCP checksums were constructed; the independent
fixture test confirms equivalent decoded packets and the IPv4 checksum.

The installed Python distribution is the separately maintained CICFlowMeter-like
package, not the original Java implementation. Its wheel SHA-256 is
`5bcef1ef131a53a037a47b007b33b5e73d4218033fdf6cb9f3208533180c30be`.
An isolated project-local environment was used. The recorded protocol files
include the dependency versions, runner hashes and fixture hashes.

## Observations

* The package CLI failed for both inputs with `tcpdump is not available`. The
  environment also reported that no libpcap provider was available. Both
  output CSVs were empty. This failure says nothing about feature accuracy.
* An explicitly separate offline API adapter submitted all three IPv4 TCP
  packets in each file to `FlowSession.process`, then called `flush_flows`.
  Both runs produced one flow with duration 1.0 second, but reported three
  forward and one backward packet, instead of two forward and one backward.
* The API reported protocol 6 for Ethernet and 2048 for Linux cooked, although
  both encapsulated IP packets use TCP (protocol 6). It also reported average
  packet lengths of 54 and 56 bytes respectively. These length values include
  link-layer framing and show that the two outputs differ; this alone does not
  establish the intended Java extractor's packet-length convention.
* The output's source and destination IPs appear reversed relative to the
  synthetic first packet, while the source and destination ports retain their
  forward ordering. The API also reports four ACKs from three ACK packets.
* Source inspection is consistent with the count defect: `Flow.__init__`
  stores the first packet, and `FlowSession.process` subsequently calls
  `add_packet` on the newly created flow. The protocol is read from
  `packet.proto`, whose meaning depends on the decoded outer layer. These are
  findings about this specific version and API route, not the canonical Java
  CICFlowMeter. A comprehensive comparison of all 27 model features was not
  warranted after these failures.

The original CLI report is at
`artifacts/experiment-009-extractor-spike/report.json`; the API observations and
environment are at `artifacts/experiment-009-extractor-api-spike/report.json`
and `protocol.json`. These artifacts include synthetic documentation-address
traffic only. The fixture test passed with the project's Python environment;
pytest is not installed in the isolated extractor environment.

## Label boundary and next step

The publisher describes attack labeling based on attacker IP addresses and
attack times, but that description does not independently establish that every
packet in `normal_13.pcap` is benign. The normal capture therefore remains a
weak source-level claim, not a validated false-positive-rate denominator.

Next, evaluate a different, explicitly versioned offline extractor against an
expanded fixture suite and the project's feature definitions. Alternatively,
a corrected adapter or fork would require its own tests and independently
demonstrated feature compatibility; neither route should use assessment data
or revise the frozen model based on these synthetic checks.
