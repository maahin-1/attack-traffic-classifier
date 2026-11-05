# PRD 01: Attack traffic classifier

Version 1.0 | 2 November 2026 | Proposed research MVP

## 1. Summary

Build an offline network-flow classifier and comparison report that show how dataset corrections change intrusion-detection results. The product helps a learner or security reviewer assess detection quality, false alerts and generalization to later traffic.

The distinctive deliverable is an auditable comparison of original and corrected data, not a high accuracy score. This is a research prototype, with no automatic blocking or production network integration.

## 2. Background

The supplied guide proposes CICIDS2017 and a comparison against corrected flows. The correction maintainers document changes to flow construction and labels and link to later correction work. The implementation must select and name a specific corrected release. [Source](https://intrusion-detection.distrinet-research.be/WTMC2021/tools_datasets.html)

Two problems shape the MVP: identifiers can enable memorization, and later days may contain attack classes absent from training. A useful report must reveal both instead of hiding them inside an aggregate score.

## 3. Objective and measurable outcomes

By the first release:

1. Generate original-versus-corrected reports using the same feature policy, time boundaries and model settings, with differences in population disclosed.
2. Account for every input row as retained, excluded or quarantined, with reasons and per-class counts.
3. Publish binary FPR, recall, precision@100 and attack-class recall with training/test support and seen/unseen status.

Proposed operating target: validation FPR at or below 1%, while maximizing binary attack recall. Report achieved test behavior without retuning. This is an experiment target, not a validated SOC requirement. If sample support cannot justify the target, report that limitation.

## 4. Market segments

**Primary: ML portfolio builders investigating network security.** They need a repeatable experiment and a defensible explanation of dataset quality. Constraint: local CPU and limited memory.

**Secondary: technical reviewers assessing research credibility.** They need split evidence, class support and false-alert implications without reading every notebook. These are proposed user segments rather than validated customer research.

## 5. Value propositions

| Part | Portfolio builder | Technical reviewer |
| --- | --- | --- |
| Who | Learner building an intrusion-detection project | Reviewer evaluating the work |
| Why | Needs evidence of useful detection | Needs to distinguish generalization from memorization |
| What before | Random-split tutorial and one score | Claims with little split or label evidence |
| How | Paired experiment configurations and leakage checks | Concise report with provenance and support |
| What after | Can explain how data choices affect conclusions | Can reproduce and challenge the findings |
| Alternatives | Generic classification notebook | Manual code and dataset audit |

The product makes data quality and evaluation choices visible enough to defend in a technical review.

## 6. Solution and requirements

User flow: select local data releases → validate and clean → inspect split/class coverage → run matched experiments → inspect metrics and comparison charts → export ranked detections.

| ID | Priority | Requirement and acceptance |
| --- | --- | --- |
| AT-P01 | Must | Record source, snapshot, hashes and row counts for both dataset variants. |
| AT-P02 | Must | Exclude IPs, ports, timestamps, flow identifiers and labels from model inputs; show the final feature list. |
| AT-P03 | Must | Use chronological train/validation/test partitions and show class coverage before training. |
| AT-P04 | Must | Produce binary attack detection and a multiclass diagnostic with explicit unseen-class limitations. |
| AT-P05 | Must | Compare original and corrected results; explain when changes include both labels and reconstructed flows. |
| AT-P06 | Must | Show FPR, precision@100, recall, confusion counts and class support; disclose daily-volume assumptions. |
| AT-P07 | Must | Rebuild reports through one documented command after setup and data acquisition. |
| AT-P08 | Should | Export ranked alerts with score, prediction and reference identifiers for review. |
| AT-P09 | Could | Add a local dashboard or attribution plots after the core comparison is complete. |

## 7. Assumptions, constraints and risks

- Local batch operation is the proposed first version. It does not capture packets or contact traffic endpoints.
- Data-release selection and license review are implementation prerequisites. The exact corrected snapshot remains a recorded configuration decision.
- Source labels may include attempted attacks. Keep that distinction in reporting; any family aggregation must be explicit.
- The dataset is a limited capture, so results do not establish performance on an enterprise network.
- Original and regenerated rows may not match. Do not describe a population comparison as a label-only causal experiment.
- Performance and runtime targets require a local benchmark before a hardware claim can be made.

## 8. Release and acceptance

Deliver in four stages: provenance and cleaning; leakage-safe splits and baseline; original/corrected comparison; reproducible report and README.

Release when AT-P01 through AT-P07 pass, the worst-supported or worst-performing classes are discussed, and the report identifies which comparisons are controlled. A low recall on unseen attacks does not block an honest research release.

Deliverables: CLI, configuration, dataset manifest, model card, metrics CSV/JSON, per-class comparison chart, exclusions audit and README. Dataset files stay outside version control. Real-time packet processing, automatic incident response and production readiness claims are out of scope.

Technical implementation and tests: [TRD 01](TRD-01-attack-traffic-classifier.md).
