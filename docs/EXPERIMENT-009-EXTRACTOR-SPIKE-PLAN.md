# Experiment 009: pinned extractor compatibility spike

Goal: test whether the independently maintained Python `cicflowmeter==0.4.0` can serve as a development-only candidate on this machine. It is a CICFlowMeter-like implementation, not the original UNB Java tool; same feature names do not establish semantic equivalence. The upstream [release page](https://pypi.org/project/cicflowmeter/0.4.0/) describes offline PCAP input and notes inactive maintenance. This spike does not select the final extractor, alter the 27-feature baseline, or certify it as an inference adapter.

Install the pinned package only in a dedicated project-local virtual environment, record Python and all resolved dependencies, and pin/hash the downloaded wheel. Do not install capture drivers, change Docker or system settings, or use live interfaces. First generate tiny, project-authored Ethernet and Linux cooked v1 fixtures representing the same bidirectional TCP packets at explicit microsecond timestamps. Test that offline processing completes and compare expected packet counts, direction, duration, and intended 27-feature schema/units. If fixture processing fails or semantics cannot be verified, record failure and do not infer compatibility. Treat any timestamp, timeout, direction, duplicate, fragmentation, IPv6 or cooked-protocol ambiguity as unresolved until separately tested.

Use only synthetic fixtures initially, no TON_IoT capture or event labels, no training/calibration/assessment/model score. Do not infer benign labels from the normal folder or from unmatched events. Record the extractor, wheel, dependencies, commands, fixture hash, output and failure evidence in a new local artifact. Candidate acceptance requires an explicit later contract including supported link-layer types, source rows omitted, flow expiration and feature semantics verified independently on representative fixtures before any dataset transformation.
# Offline API follow-up

The CLI failed on both synthetic cases because its offline filter requires an
unavailable tcpdump/libpcap provider. As a separate feasibility check, use
Scapy's offline PcapReader to feed IPv4 TCP/UDP packets to the pinned package's
FlowSession.process and flush_flows API. Use only the existing two synthetic
fixtures. Record the fixture and runner hashes, package environment, observed
rows, errors, and direction and duration observations. This is not a CLI fix,
evidence of Java CICFlowMeter equivalence, or authorization to process real
traffic. Preserve the original CLI failure report.
