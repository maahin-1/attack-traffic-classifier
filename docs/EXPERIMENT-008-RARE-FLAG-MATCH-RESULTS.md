# Experiment 008: rare-flag packet and CSV-flow match

## Result

The two previously identified ECE+CWR packets are three microseconds apart and share one bidirectional TCP tuple. A full search of the seven 03-11 CSV members found **one row with that tuple** among 20,364,525 rows, in `03-11/Syn.csv` record 509818. The source row has label `Syn`, but that label is not independent ground truth. Matching was based on tuple and TCP protocol, with no timestamp or label filter. Raw endpoint identifiers were not written to the report.

Under the previously observed **PCAP clock = CSV clock + 3 hours** hypothesis, the matching CSV flow begins at PCAP time 2018-11-03 19:46:50.527536 UTC. Its reported 1,374,705 microsecond duration ends at 19:46:51.902241 UTC. The first and last of ten tuple packets within that interval match those endpoints exactly. The ten contain six packets in the CSV forward direction and four in the reverse direction, matching the source row's reported 6/4 counts. These endpoint and direction/count agreements in a different time window support that specific clock-alignment hypothesis for this candidate; they are not an independent time standard and do not prove a dataset-wide timezone rule.

The two ECE+CWR+SYN packets occurred at 19:46:50.527385 and 19:46:50.527388 UTC: **151 and 148 microseconds before** the inferred flow start. They are outside this row's reported interval under the three-hour hypothesis. The complete scanned member contains twelve matching-tuple packets: those two before the interval, ten inside it, and none after it. Thus the CSV row is a plausible match to the later ten-packet flow, but it does **not** establish that either rare-flag packet belongs to that row. No second source row for the tuple was found in the searched archive. This does not prove what happened to the earlier packets or why they lack a matching row.

The row's first in-window packet carries RST+ACK; its CSV `SYN Flag Count` and `URG Flag Count` are both 1 while its ECE and CWE fields are 0. This is compatible with the earlier exploratory first-packet associations, but because the ECE/CWR packets fall outside the selected interval, their absence in those CSV fields is not evidence of how ECE/CWR are encoded. Do not infer a correction from this case.

## Verification and limits

A second reader independently checked the packet flag bytes and reread the specific CSV row without using the original packet decoder. This checks the observed bytes and row, but not the source clock against a separately synchronized reference. The full search read all seven CSV members through ZIP CRC verification; the PCAP member also passed its ZIP CRC and its previously recorded SHA-256 check. Such checks establish internal integrity, not publisher authentication. The last member has a truncated final packet record, excluded from the scan. Other members were not searched for the target tuple; earlier or later reuse outside the examined segment remains possible. The apparent packet pairs may reflect capture duplication or repeated packets; neither interpretation has been proven.

The search uses exact textual IP/port representations in the CSV and the normalized IPv4/decimal representation decoded from PCAP. Alternative textual spellings could evade it. The analysis is post-hoc, based on one tuple, and neither validates the producer implementation nor estimates a general error rate. No model, threshold, or flag-feature policy was changed. The assessment capture was already consumed and cannot be used as a fresh final assessment.

## Artifacts and next step

The pre-scan plan is [here](EXPERIMENT-008-RARE-FLAG-MATCH-PLAN.md). The [machine-readable search](../artifacts/experiment-008-rare-flag-match/report.json) has SHA-256 `485ee4a1d89cd251b1da16eb186a94b7c8044ef29514c5bcea7f72052bc5e10c`; its protocol records input and implementation hashes. [Independent byte/row verification](../artifacts/experiment-008-rare-flag-verification.json) is supplementary and post-hoc.

Keep the disputed flag features excluded from shared cross-release models. Further flag investigation requires a known extraction build or additional independently matched flows with known boundaries, not a remapping based on this tuple. In parallel, advance the research release through clean-environment reproduction and an AT-P01–AT-P07 evidence review; model generalization requires a separately reserved independent capture.
