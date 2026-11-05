# Experiment 008: feature feasibility on development data

This is a descriptive feature-availability and collision study, not a model-accuracy experiment. It uses only the previously prepared, label-independent 1% CICIDS2017 samples from Monday–Wednesday (3–5 July 2017). These rows have already been used for model development. No CIC-DDoS2019 assessment rows or model scores are used. The sampled source references were checked against the original archives for labels and all 27 existing features before adding protocol and seven flag-count fields. Source archives and sample artifacts were fingerprinted before and after the scan.

Candidates: `Protocol`, plus `FIN`, `SYN`, `RST`, `PSH`, `ACK`, `URG`, and `ECE Flag Count`. The `CWE`/`CWR` column is omitted pending an explicit cross-release semantic decision. Four groupings use the same complete-case sample and source-provided binary label mapping: the existing 27 features, those features plus protocol, plus the seven flag fields, and plus both. An exact conflict group contains both benign and attack labels. The minority-label count is a lower bound on row errors for a deterministic classifier restricted to the grouping features, assuming the supplied labels; it is not measured classifier error.

| Dataset | Valid sampled rows | Added fields | Distinct groups | Conflicting groups | Rows in conflicting groups | Minority-label lower bound |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| Original | 16,784 | None | 14,352 | 49 | 932 | 275 |
| Original | 16,784 | Protocol | 14,353 | 49 | 931 | 274 |
| Original | 16,784 | Seven flags | 14,486 | 49 | 851 | 233 |
| Original | 16,784 | Protocol and flags | 14,486 | 49 | 851 | 233 |
| Corrected | 11,915 | None | 11,876 | 0 | 0 | 0 |
| Corrected | 11,915 | Protocol, flags, or both | 11,876 | 0 | 0 | 0 |

The original sample had two invalid base-feature rows, excluded consistently before all comparisons; neither dataset had invalid candidate fields among analyzed rows. Flag fields reduced the original sample's conflicting rows by 81 and the minority-label lower bound by 42, but all 49 conflicting groups remained. Protocol alone changed one conflicting row. The corrected sample had no conflicting baseline groups, so this sample cannot demonstrate that these fields resolve corrected-data conflicts. These collision counts do not measure recall or prove that a new model will transfer.

## Feature-semantics gate

Column names do not establish equivalent flag extraction. In the original development sample, all 16,784 `SYN Flag Count` and `ACK Flag Count` values were 0 or 1. In the corrected sample, 5,196 of 11,915 SYN counts and 5,558 of 11,915 ACK counts exceeded 1. The correction researchers report that the original CICIDS2017 flag counts reflected only the first packet because of an extractor bug, fixed in the upstream tool in October 2019; they say other datasets produced with earlier CICFlowMeter-V3 versions may also be affected. The exact CIC-DDoS2019 producer version remains unverified. Current upstream source alone does not prove which version generated any particular CSV. [Researchers' original documentation](https://intrusion-detection.distrinet-research.be/WTMC2021/extended_doc.html) · [Current upstream implementation](https://github.com/ahlashkari/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java) · [Correction implementation](https://github.com/GintsEngelen/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java)

Do not treat the original and corrected flag fields as interchangeable or assume that converting full-flow counts to booleans reconstructs first-packet flags. The end-of-flow availability and semantics of any candidate must match the intended serving pipeline. Protocol and flags can also become capture-environment shortcuts; packet/event ground truth and a separate network are needed to assess that risk. IP addresses, ports, and timestamps are not added to this candidate set.

The upstream historical change is identifiable: [commit `ed1d6bcb` on 15 October 2019](https://github.com/ahlashkari/CICFlowMeter/commit/ed1d6bcbdefe161be51ac278f76be995f7121482), parent `99dc8276`, enables `checkFlags(packet)` for subsequent packets in `BasicFlow.addPacket`; the parent calls it for the first packet but comments out the later call. The same change also enables bulk and subflow updates, so comparisons between those entire versions may differ for reasons beyond flags. This locates a reproducible before/after code boundary; it does not prove which build produced the CIC-DDoS2019 CSVs. The dates read from the CSVs are literal source-clock values, not independently verified capture dates.

The complete local results and value distributions are in `artifacts/experiment-008-feature-feasibility/report.json` (SHA-256 `b81abec4e27a412943428f76fd7b9ec6af98d1037d25457b6a3c8cec308ce822`), with input hashes and selection policy in `protocol.json`. Both sampled flow files match their Experiment 006 stage-B fingerprints. A focused synthetic check verifies that the collision calculation responds correctly when flags separate labels.

## CIC-DDoS2019 calibration-day development sample

The previously consumed 2018-12-01 calibration archive was scanned in full, applying the predeclared BLAKE2b-based 1% selection independently of labels. The fixed source and implementation fingerprints, selection rule, feature list, and row policy were recorded before scanning in `artifacts/experiment-008-ddos-development/protocol.json`. The scan visited 50,063,112 source rows and selected **500,805**, all with valid candidate fields: 500,231 attack-labeled and 574 benign-labeled. It did not access the 2019 assessment archive or train a model.

| Added fields | Distinct sampled groups | Conflicting groups | Rows in conflicting groups | Minority-label lower bound |
| --- | ---: | ---: | ---: | ---: |
| None | 107,291 | 8 | 12,710 | 21 |
| Protocol | 107,297 | 8 | 12,709 | 21 |
| Seven flags | 107,303 | 6 | 11,546 | 13 |
| Protocol and flags | 107,303 | 6 | 11,546 | 13 |

On this sample, adding flags reduces the number of conflicting groups by two and their row membership by 1,164 (9.16%). Protocol alone removes one row from a conflicting group without resolving a conflicting group. The minority-label lower bound falls from 21 to 13 rows with flags. These are sample-specific collision properties, not accuracy or recall estimates; the sample contains only 574 benign rows and inherits this lab capture's labels and class imbalance.

Every sampled 2019 flag-count value was 0 or 1. Only **8 of 500,805** sampled rows had `SYN Flag Count` equal to 1, while **15,878 rows were SYN-labeled**. Therefore at least 15,870 of those SYN-labeled rows (99.95%) have a zero SYN count in this sample, regardless of which labels the eight nonzero rows have. This is compatible with a feature-extraction or labeling mismatch, but the aggregate data do not establish the cause. The first-packet bug described above is a possible explanation, not a verified identification of this archive's producer version; packet-level evidence or a pinned extraction build is needed. In the corrected 2017 sample, by contrast, 5,196 of 11,915 SYN counts exceeded 1. Do not pool these columns as though their measurement were proven identical.

The complete results are in `artifacts/experiment-008-ddos-development/report.json` (SHA-256 `565a1d46a3b711481d1673e9823eee63fe38dfcf97ac28e37df995a2e9b5ad15`). Two focused synthetic tests cover collision counting. Neither development study measured model accuracy, and the 2019 assessment remains consumed.

## Next step

The user subsequently supplied one 2019 PCAP segment. A focused comparison of 20 SYN-labeled source rows with matching packet tuples found a flag-field discrepancy that neither simple first-packet-only nor full-flow flag counting explains under the observed matching assumptions. See `docs/EXPERIMENT-008-PACKET-PROBE-RESULTS.md`. The exact producer and any CSV processing remain unknown. Continue tracing the writer and extraction semantics before treating these fields as equivalent across releases. If equivalent features can be produced at inference time, define a development-only model comparison using consistent extraction, group-aware splits, and a fixed false-positive rule. Freeze the chosen model and threshold before a new independent capture; do not reuse the consumed 2019 assessment as a final test.
