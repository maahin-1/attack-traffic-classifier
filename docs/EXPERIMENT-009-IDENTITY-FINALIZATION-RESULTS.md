# Experiment 009: experimental identity, finalization and TCP direction

## Decision

Three narrow fixes have been demonstrated on synthetic fixtures: CSV endpoint
identity follows the flow's directional endpoints; finalization uses the
flow's last packet timestamp; and SYN-ACK-first flows use the first observed
packet as forward. These changes exist **only in disposable project-local
extractor copies**. They do not establish compatibility with Java
CICFlowMeter or with the historical training-data extractor, and must not yet
be used to score TON_IoT captures.

## Identity and finalization

The [preregistered plan](EXPERIMENT-009-IDENTITY-FINALIZATION-PLAN.md) compared
the earlier sample-standard-deviation variant with a second variant. All 24
offline CLI runs succeeded, without ERROR in stderr. Fixture input readback and
output assertions passed.

* A three-packet UDP flow started with two packets from `198.51.100.2:53`,
  followed by one reverse packet. The corrected CSV named that first endpoint
  as its source and reported 2 forward and 1 backward packet. Previously the
  identity columns were in the opposite order.
* For two separate singleton flows observed a second apart, the previous
  variant reported one second of idle time for the first flow; the new variant
  reported zero for both. In the timeout case, it removed the 120.000001-second
  idle value previously attached to a zero-duration singleton. Flow counts and
  boundaries stayed the same on these fixtures.
* Across all 12 pairs, changes were confined to identity and idle fields;
  the earlier packet-length standard-deviation values were preserved. A direct
  callback check returned the same lookup key before and after the CSV-only
  identity change. Equivalent Ethernet and Linux cooked TCP fixtures still
  produced identical rows.

These finalization semantics are chosen for the experiment; no Java runtime was
available to independently confirm them. Active/idle standard deviations and
other implementation details still require a separate compatibility audit.

## SYN-ACK-first follow-up

The [additional plan](EXPERIMENT-009-SYNACK-PLAN.md) checked a TCP capture
starting with a SYN-ACK from `198.51.100.2:443`, followed by an ACK in the
opposite direction. Packet readback confirmed the inputs. Both earlier variants
reported 2 forward and 0 backward, and named the opposite endpoint as source.

The [correction plan](EXPERIMENT-009-SYNACK-FIX-PLAN.md) then applied the
first-observed-packet convention to both SYN-ACK initialization paths in a
third isolated copy. That variant reported the expected source, 1 forward and
1 backward packet. All other 12 prior fixture outputs were unchanged; all 13
CLI runs and the callback check passed, and prior standard-deviation and
singleton idle assertions remained true. The correction also changed other
direction-dependent values in the SYN-ACK case, as expected. This tests only
the one specified TCP sequence.

The first attempt to run the SYN-ACK diagnostic stopped before invoking the
extractor because the runner passed a string rather than a Path to its hash
helper. Its partial `experiment-009-synack` folder was preserved; the corrected
run and evidence are in `experiment-009-synack-v2`.

## Evidence and remaining boundary

Detailed output rows, package/source hashes, exact patches and fixture hashes
are in `artifacts/experiment-009-identity-finalization/`,
`artifacts/experiment-009-synack-v2/`, and
`artifacts/experiment-009-synack-fix/`. The variants retain the upstream MIT
license in their local test directories. No real captures were processed; the
model, threshold, label policy and flag-feature exclusion remain unchanged.

Before model use, compare against a reproducible Java reference or provide a
complete independently justified feature contract; test nonzero active and
idle variance, flow timeout and TCP termination behavior, fragmentation and
capture edge cases; and establish the scope of historical extractor and label
uncertainty. The `normal_13` file remains a weak source-level benign claim, not
a validated false-positive-rate denominator.
