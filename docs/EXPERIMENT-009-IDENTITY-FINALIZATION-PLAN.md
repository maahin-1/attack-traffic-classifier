# Experiment 009: experimental identity and finalization fixes

This synthetic-only follow-up builds on the earlier disposable source variant
with its two packet-length sample-standard-deviation changes. Preserve upstream
archive verification, the earlier variant hashes, and the prior results. Create
a new isolated copy and record the complete diff against upstream. Never change
the pinned source or prior variant.

Candidate changes: (1) in the CSV-only path, render endpoint identity from
the flow's stored forward/backward endpoints rather than its sorted lookup key;
retain the callback's existing lookup key; (2) use the flow's own `last_seen`
time during finalization rather than the analyzer's most recent packet time.
This excludes gaps after the last flow packet from the flow's active/idle
statistics. These are experimental semantics, not claimed Java parity.

Run the prior and new variants on the ten previous fixture captures plus:

* three UDP packets with a reverse-first endpoint order (two packets from
  `198.51.100.2:53` and one in reverse). Expect that endpoint in CSV source,
  2 forward and 1 backward, for the new variant;
* two different UDP flows interleaved, each containing one packet a second
  apart. Each is a zero-duration flow, whose final idle value must be zero;
* the existing timeout-above-boundary case: both singleton idle values should
  be zero in the new variant and packet counts and flow boundaries unchanged.

Record all 27 feature fields and full rows; permitted differences: CSV identity
fields and active/idle-derived fields due solely to finalization timing. Any
other difference is a failure requiring investigation. Verify fixture packet
identities independently with Scapy readback, test TCP and UDP paths, verify
no effect on callback lookup-key behavior with a direct API check, and record
hashes, dependency versions, output and stderr. Do not use real PCAPs or model
inference. The limited correction and fixture passes cannot establish full
feature compatibility, historical producer provenance or labeling validity.
