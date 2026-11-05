# Experiment 009: second offline extractor results

## Decision

`pycicflowmeter` is a more promising offline feasibility candidate than the
first Python package, but it is **not yet compatible enough to feed the frozen
model**. A controlled packet-length standard-deviation example exposes a
meaningful difference from the current published Java implementation's
statistical convention. Historical producer parity remains unverified.

## Source and environment

The tested source was [pycicflowmeter](https://github.com/Shahid-Wani/pycicflowmeter)
commit `4432a32e05491c110f78fe80a59ab733b145d2cb`; the downloaded archive's
SHA-256 was `db4a1b578fb159503db963bcba48300d0ad42fc9237d8cf1c62dbf05e3455850`.
The source files were checked against that archive before and after each run.
The project-local isolated Python environment and the already installed Scapy
were used. Although Scapy warned that no libpcap provider was available, all
five offline CLI cases exited successfully. No driver was installed.

## Controlled observations

| Synthetic case | Expected | Observed |
| --- | --- | --- |
| Three TCP packets, Ethernet | 2 forward, 1 backward; TCP 6; 1,000,000 µs | Matches; flow IAT mean 500,000 µs |
| Same TCP packets, Linux cooked v1 | Same as Ethernet | All output fields match Ethernet |
| Single UDP packet | 1 forward, 0 backward; UDP 17; zero duration | Matches |
| Bidirectional UDP, two seconds apart | 1 each direction; duration and flow gap 2,000,000 µs | Matches |
| Two distinct UDP five-tuples | Two one-packet flows | Matches |

All 27 model-feature columns were present under explicitly mapped names and
none of these rows used a `-1` or empty placeholder for those fields. This
checks presence, not the correctness of all 27 feature calculations. Synthetic
outputs contain documentation addresses only.

In a separate preregistered follow-up, two forward UDP packets had payload
lengths 4 and 8 bytes. The capture was read back to confirm those lengths. The
extractor reported forward packet-length standard deviation **2.0**, the
population standard deviation. The sample standard deviation is sqrt(8),
approximately **2.828427**. The candidate source uses Python `statistics.pstdev`
for directional packet lengths, while the currently published Java
[BasicFlow source](https://github.com/ahlashkari/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java)
uses Apache `SummaryStatistics.getStandardDeviation`; Apache documents its
variance as [bias-corrected sample variance](https://commons.apache.org/proper/commons-math/javadocs/api-3.6.1/org/apache/commons/math3/stat/descriptive/SummaryStatistics.html).
This is a source-level comparison, not an actual run of Java on the fixture,
and it does not establish the exact historical dataset-producing revision.
The model includes both directional packet-length standard deviations, so
this difference can affect model inputs. The candidate also uses population
standard deviations for active/idle statistics; behavior across examples and
the other model features requires further testing.

The raw observations and environment are in
`artifacts/experiment-009-second-extractor/report.json` and `protocol.json`;
the unequal-length result is in
`artifacts/experiment-009-std-fixture/report.json`. The basic fixture checks
and readback assertions passed. The earlier project's fixture pytest also
passed in its Python environment.

## Boundaries and next work

No real TON_IoT capture was processed, no feature mapping was approved for
inference, and the frozen model, threshold and flag-feature exclusion remain
unchanged. Normal-capture labeling remains unverified. Next, investigate a
reproducible Java CICFlowMeter runtime or a separately versioned correction of
the Python candidate, then compare both against a wider set of synthetic
fixtures covering nonzero variance, active/idle gaps, termination and timeout
boundaries. A corrected fork would still need independent evidence of historical
extractor compatibility before model assessment.
