# Experiment 009: first-packet TCP direction follow-up

Create a third disposable variant from the source hashes recorded by the
identity/finalization experiment. In both TCP flow-creation paths, initialize
forward endpoints from the SYN-ACK packet's source and destination, consistent
with this experiment's first-observed-packet convention. Preserve the existing
handling of other TCP packets and all previous experimental fixes. Save the
complete diff relative to upstream, source hashes and outputs. This is a
first-packet convention test, not proof of Java or historical dataset parity.

Compare the second and third variants on the 12 prior synthetic cases and the
two-packet SYN-ACK-first PCAP. Verify the latter starts from
`198.51.100.2:443`, output source matches, and output counts are 1 forward and
1 backward. No values on the earlier 12 fixtures should change. Verify process
exit and stderr, callback lookup-key stability, and retained earlier sample
standard-deviation and timeout assertions. No real data or inference.
