# Experiment 009: scoped extractor correction and boundary results

## Decision

The isolated two-calculation correction demonstrates how sample standard
deviation changes the two directional packet-length fields. It does **not**
make the candidate ready for model inference. Independent identity and timeout
observations show that additional extractor semantics must be resolved first.

## Environment and reproducibility

`java` was not found on PATH or in the common installation locations checked.
Docker's CLI could not connect to its local engine; `wsl --list --quiet` returned
access denied in this environment. No Java comparison was run and no system
runtime or driver was installed. Absence from these locations does not prove
that Java is absent everywhere on the computer.

The preregistered plan is
[EXPERIMENT-009-CORRECTION-SPIKE-PLAN.md](EXPERIMENT-009-CORRECTION-SPIKE-PLAN.md).
The variant is a disposable local copy of the pinned upstream source. Its exact
two-line change, source hashes, Python environment, synthetic PCAP hashes and
all output rows are retained in `artifacts/experiment-009-correction-spike/`.
The upstream archive and extracted source were verified before and after the
run. The variant retains the upstream MIT license. All 20 offline CLI runs
exited zero and their stderr contained no ERROR lines; Scapy also reported that
no libpcap provider was available, without preventing offline processing.

## Findings

* With forward payload lengths [4, 8] and backward lengths [3, 9], the
  unchanged extractor reports standard deviations 2 and 3. The variant reports
  sqrt(8) and sqrt(18), matching the intended sample calculations. For whole
  flow gaps [1, 2, 1] seconds, both report sample IAT standard deviation
  approximately 577,350.269 microseconds. On the ten fixture pairs, no output
  fields other than the two targeted standard deviations differed between the
  upstream and the variant.
* In a two-packet UDP flow whose first packet went from `198.51.100.2:53` to
  `192.0.2.1:12345`, both CSVs reported the latter endpoint as the source.
  Input readback confirms the first packet's direction. Source inspection
  shows that the CSV identity comes from a sorted flow key, while forward
  direction is separately initialized from the first UDP packet. The equal
  directional packet counts in this specific fixture do not independently prove
  that all directional features are assigned correctly.
* With a 120-second flow timeout, two packets separated by 119.999999 or
  120.000000 seconds were emitted as one flow, whereas a 120.000001-second gap
  produced two singleton rows. For the first singleton, the extractor reported
  zero flow duration but `Idle Mean = 120000001` microseconds. Source inspection
  shows that finalization can append the time from the last packet to the
  later packet that caused finalization. That value reaches beyond the row's
  observed packet interval and is a model-feature compatibility concern.
* The six-packet activity-gap fixture produced one row. Both variants reported
  `Active Mean = 5999999.5`, `Active Std = 4999999.5`, and
  `Idle Mean = 5000001` microseconds. These are observations, not independently
  validated Java outputs; the candidate still calculates active/idle standard
  deviations using population statistics.
* The ACK, forward FIN, reverse FIN and final ACK case produced one four-packet
  flow in both variants. This one sequence does not establish general TCP
  termination behavior.

The published current Java
[flow generator](https://github.com/ahlashkari/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/FlowGenerator.java)
is a useful source for later comparisons, but these results are not a Java
runtime comparison and do not establish which historical extractor produced
the model's training CSVs.

## Validation and boundary

Readback assertions verified the reverse-first UDP packet, targeted numerical
results, all successful CLI exit codes, variant differences, timeout row counts,
the singleton idle observation, and the four-packet termination observation.
Only synthetic documentation-address PCAPs were used. No model, threshold,
flag-feature exclusion, real capture or dataset labels changed.

Next, evaluate whether a reproducible Java reference can be supplied in a
project-local environment and use it to compare these exact PCAPs; otherwise,
first fix and separately validate identity and flow-finalization semantics in
an experimental fork. Either route must compare all 27 features and account
for historical extractor provenance before any model assessment.
