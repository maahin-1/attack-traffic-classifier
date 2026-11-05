# TON_IoT development event timestamp diagnostic

## Result

The [first diagnostic](EXPERIMENT-009-UNMATCHED-DIAGNOSTIC-PLAN.md) reconstructed the same 50,000 distinct, CSV-order-selected TCP/UDP IPv4 event keys from the consumed scanning1 development probe. It reproduced the earlier **27,055 same-second matches** in either direction. Every one of the remaining **22,945** keys has a same-tuple packet within one adjacent integer second. Thus all 50,000 have a tuple match either in the event's integer second or within one second in the examined capture. The original sample and the wider time comparison are exploratory, not independent observations or a model metric.

| Closest observed tuple-match category | Event keys |
| --- | ---: |
| Same integer second | 27,055 |
| Adjacent second, with no same-second match | 22,945 |
| Only within 2–5 seconds | 0 |
| Only within 6–60 seconds | 0 |
| Only elsewhere in capture | 0 |
| Tuple not observed in the supported packet subset | 0 |

These are **event-to-packet tuple matches**, not proven flow-to-event matches. Same 5-tuples can recur, matches can be repeated packets, and packet timestamps and source labels may carry their own errors. The scan excludes ICMP, noninitial IPv4 fragments, and other unsupported traffic; the selected sample is not representative of all dataset records.

## Subsecond follow-up

A separate predeclared [subsecond check](EXPERIMENT-009-TIMESTAMP-ROUNDING-PLAN.md) reread the original microsecond-resolution PCAP and reproduced both earlier totals. For **all 22,945 adjacent-only keys**, at least one matching packet occurred in the PCAP second immediately before the CSV's event second, and at least one such packet was in that second's latter half (microseconds >= 500,000). Sixty of these keys also had a tuple match in the PCAP second after the CSV event second; categories can overlap.

This is consistent with rounding a packet timestamp to the nearest second for the selected examples. It does **not** prove the publisher's conversion rule, establish that all source rows derive from the matched packet, or justify blindly shifting timestamps. Flow boundaries, segmentation, labels, capture completeness and timezone alignment need separate validation. No labels were changed and no unlabeled packet was treated as benign.

## Normal-capture inventory

The publisher's accessible `Network_dataset_pcaps/normal_pcaps` listing contains 15 files. A candidate, `normal_13.pcap`, was displayed as **0.99 GB**. The `normal` name is source metadata, not verification of benign ground truth, and its temporal coverage and independence from attack captures are unknown. If acquired, it is reserved for **development inspection**, not final assessment; verify actual size/hash, capture coverage and source labeling before use. No normal capture was downloaded by this diagnostic.

Subsequently the user supplied that file for development; see the [normal13 results](EXPERIMENT-009-NORMAL13-RESULTS.md). Its benign status is still unverified.

## Evidence and verification

The [window diagnostic](../artifacts/experiment-009-unmatched-diagnostic/report.json) has SHA-256 `0afe446238bea78b028d485ab343ef3f2400c9d4e48cad1062c279d107dbc40f`; two focused tests cover disjoint categories and duplicate matching. The [subsecond report](../artifacts/experiment-009-timestamp-precision/report.json) has SHA-256 `c64545e92659013bd26d249f8d0a772b3050a9fe82dd06c4354f9e4c05be74a1`. It independently replayed the fixed source selection, reproduced the first diagnostic's counts, checked input and implementation hashes before and after, verified the capture member's previously recorded SHA-256, and fully read the ZIP member so its CRC was checked. Those integrity checks do not authenticate publisher provenance.

No model was trained, calibrated or scored. The final independent holdout is still unselected, and the disputed flag-feature exclusion remains in place. The next work is to inspect explicitly sourced normal-traffic evidence and develop/test a documented packet-to-flow and label-alignment policy on development captures before freezing a separate assessment.
