# Experiment 009: feature and capture boundary characterization

## Decision

The experimental extractor is **not ready for model assessment**. Controlled
tests found population rather than sample active/idle standard deviations,
partial payload accounting for fragmented IPv4 UDP, and negative interarrival
time when input packet timestamps are out of order. These are observations of
the pinned experimental Python variant, not results from Java CICFlowMeter.

The [plan](EXPERIMENT-009-FEATURE-BOUNDARY-PLAN.md) defined the independent
timing calculations and synthetic cases before execution. Seven offline CLI
runs exited zero, and no ERROR lines were logged. A successful exit therefore
did not by itself establish that the emitted features met the research
contract. No real capture, model or threshold was used or changed.

## Results

| Case | Observation and implication |
| --- | --- |
| Active/idle variance | For packets at 0, 1, 7, 9, 17 and 20 seconds and a 5-second activity threshold, observed active intervals were consistent with [1, 2, 3] seconds and idle intervals with [6, 8] seconds. Mean, minimum and maximum matched the preregistered interval calculations. The extractor reported active std **0.816497 s** and idle std **1 s**, the population values; the stipulated sample values are **1 s** and **1.414214 s**. This is a difference from the test contract, not proof of the historical producing implementation. |
| Exactly 5-second gap | It remained in the same active interval; the output reported no idle period. This characterizes the tested `>` threshold. |
| Equal timestamps | Two opposite-direction UDP packets produced one zero-duration flow with one packet in each direction and zero IAT. |
| Out-of-order timestamps | Packet times 0, 2, 1 seconds generated a timestamp-anomaly warning and a flow IAT minimum of **-1 s**. Handling this input needs an explicit ordering and rejection policy before assessment. |
| TCP reset | An ACK, reverse RST and later ACK produced two flows containing all three packets in total. In this implementation the RST began the second flow. This one test does not establish general termination parity. |
| IPv4 fragmentation | One 40-byte UDP payload, fragmented into three IPv4 packets, produced a flow with **8 payload bytes**. The same unfragmented datagram produced **40**. Independent readback reassembled the three IP payload slices byte-for-byte and confirmed they are the same UDP datagram; only the first fragment was decoded as UDP by the candidate. The difference is a coverage limitation and not a claim about Java's behavior or every possible fragmentation convention. |

The earlier timeout fixture showed one flow below and at 120 seconds, and two
singleton rows just above that boundary; the experimental finalization fix
removed idle time beyond each singleton's observed interval. No statement of
Java runtime equivalence follows from this.

## Reproducibility and follow-up

The complete synthetic packet readback, output rows, stderr, fixture hashes,
source hashes and dependency versions are under
`artifacts/experiment-009-feature-boundaries/`. Assertions independently
checked the interval arithmetic, warnings, RST packet totals, and exact IPv4
fragment reassembly. The runtime still warned that no libpcap provider was
available, but offline file processing completed.

Next specify and test a fail-closed input policy for out-of-order timestamps
and IP fragmentation, and separately address active/idle standard deviation
if the chosen reference contract calls for sample statistics. A reproducible
Java comparison and historical provenance are still needed before any claim of
training-feature parity. The normal capture's benign labeling remains
unverified, and the disputed TCP flag features remain excluded.
