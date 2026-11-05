# Experiment 009: synthetic preflight and active/idle experiment

## Decision

A standalone, conservative preflight now rejects the two observed classes of
problem input: IPv4 fragmentation and timestamp decreases. A separate,
disposable extractor variant implements the chosen sample-standard-deviation
contract for active and idle periods. Neither is integrated into model scoring,
and neither establishes equivalence to the original Java extractor or the
historical producer of the model's training CSVs.

## Preflight

The [policy](EXPERIMENT-009-PREFLIGHT-POLICY.md) accepts only nonempty classic
PCAPs containing complete IPv4 TCP/UDP frames on Ethernet or Linux cooked v1.
It checks every record, accepts equal timestamps, rejects a decrease in global
file order, and rejects IPv4 fragments and unsupported or structurally
incomplete input. It does not reassemble, reorder, extract or score packets.
It reports only aggregate counts or the first rejection reason and index.

The implementation is `scripts/experiment009_pcap_preflight.py`. Tests include
both byte orders and microsecond/nanosecond PCAP formats, both link types,
equal and decreasing timestamps, first and later fragments, malformed IP/TCP/
UDP, unsupported protocols, incomplete capture lengths, truncated files and
empty PCAPs. The targeted preflight and prior fixture suite passed **17 tests**
using a project-local pytest temporary directory. An initial attempt using
pytest's default temporary directory failed before test execution because it
could not create that directory; the project-local rerun passed.

On the earlier synthetic fixtures, preflight accepted the six-packet timing
fixture, the equal-time fixture and the unfragmented UDP datagram. It rejected
the decreasing-timestamp fixture at packet 3 and the fragmented datagram at
packet 1. The normal_13 cooked protocol 0x0003 is outside this narrow policy;
no real capture was scanned, and a rejection would not establish that the
underlying traffic is benign or malicious.

Preflight is a screening tool, not proof of source authenticity, checksums,
complete traffic collection, model feature compatibility or input immutability
between checking and future extraction. Any future integration must bind the
checked bytes to the extractor and explicitly address unsupported traffic.

## Active and idle standard deviation

The [experiment plan](EXPERIMENT-009-ACTIVE-STD-PLAN.md) specified sample
statistics for a disposable source variant. On independently defined active
durations [1, 2, 3] seconds and idle durations [6, 8] seconds, it reported
active std **1 second** and idle std **1.414214 seconds**, as stipulated.

Twenty synthetic cases ran successfully and were compared with saved prior
variant outputs. Differences were confined to `Active Std` and `Idle Std`; two
cases changed, and no flow counts changed. One of those cases was the explicit
nonzero-variance fixture. The input set includes fragmented and disordered
fixtures solely for a controlled before/after calculation comparison; the
standalone preflight would reject both.

Full rows, source/fixture hashes, environment and the upstream-to-variant diff
are saved under `artifacts/experiment-009-active-std/`. The source copy remains
in the project-local test directory and retains the upstream MIT license.
The targeted numerical and output-difference assertions passed. No real data
was scanned, extracted or scored, and model thresholds, flag exclusions and
label policy remain unchanged.

## Remaining work

The sample-standard-deviation variant is a research choice. An actual pinned
Java reference comparison and evidence about the historical dataset extractor
remain open. Before any assessment, also define supported-traffic coverage,
address discarded or unsupported traffic without selecting on model outcomes,
and establish independent label provenance and a protected evaluation source.
