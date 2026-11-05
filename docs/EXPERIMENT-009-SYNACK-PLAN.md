# Experiment 009: SYN-ACK-first synthetic check

With the same previous and new experimental variants, process two TCP packets:
a SYN-ACK from `198.51.100.2:443` to `192.0.2.1:12345`, followed one second
later by an ACK in the opposite direction. Read back the PCAP independently.
If forward means the first observed packet, the expected direction counts are
one forward and one backward and the CSV source is the first packet's sender.
Record the actual outputs and errors. This fixture tests a semantic hypothesis;
it is not an actual run of Java CICFlowMeter or evidence about historical data.
Use synthetic traffic only and preserve hashes of the previous protocol,
variants, fixture, plan and runner.
