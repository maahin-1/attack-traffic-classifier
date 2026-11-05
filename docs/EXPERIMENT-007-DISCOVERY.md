# Experiment 007 discovery: target-domain threshold transfer

## Why this is next

Experiment 006 showed a threshold-transport problem. On CIC-UNSW, the original-data candidate's frozen 0.754373 threshold caught 0/14,480 attacks on 22 January and 4/75,103 in the pooled February block. Its 99th score percentile was only 0.445 or lower. The corrected candidate's frozen 0.061953 threshold raised recall to about 16.2%, but benign FPR rose to 2.03% and 2.35%. The corrected candidate's mean benign score was about 0.0265, similar to the attack means of 0.0257 and 0.0243. Neither candidate met the 1% FPR rule.

The consumed mirror also has 5,356 repeated rows with conflicting binary labels across 723 exact 27-feature vectors. A total of 796,806 repeated feature rows cross the two assessment blocks. This makes flow counts much less independent than their raw size suggests. Full score distributions and exact score-stream reproduction are in `artifacts/experiment-006-postmortem/`.

These findings support a threshold-transfer experiment before another model-weight change. Keep the Experiment 006 bundles fixed. Select a new source with one capture day for calibration and a different, predeclared day for final assessment. Choose thresholds on the calibration day under the existing observed benign-FPR <=1% rule, freeze them, and score the second day once. Report the unchanged Experiment 006 thresholds as a reference. Do not use CIC-UNSW again for tuning or final evaluation.

## Candidate source review

| Source | Useful evidence | Main limitation | Current status |
| --- | --- | --- | --- |
| CIC-DDoS2019 | Official documentation describes two capture days, PCAP and CICFlowMeter-V3 CSV, and different DDoS schedules by day. Local CSV archives now confirm the feature schema, capture dates, and attack-family groups. | Narrow DDoS scope, one lab/testbed. The official schedule table reverses the day headings relative to its prose and the archive contents. | Selected source; inventory complete. Freeze explicit archive/date roles and feature aliases before calibration. |
| CSE-CIC-IDS2018 remaining capture days | Official material describes seven attack scenarios, per-day PCAP and CICFlowMeter-V3 features. The project has already examined 14–16 February, so other days may supply additional temporal blocks. | Same synthetic testbed and dataset lineage as earlier 2018 work. It would support a narrower same-testbed transfer claim. Full acquisition size and precise unconsumed-day inventory need confirmation. | Fallback if CIC-DDoS2019 cannot be acquired. |
| TON_IoT network PCAP | Separate UNSW Canberra IoT/IIoT testbed, with network PCAPs and ground-truth event timestamps/IPs. This is a more distinct operational domain. | Published processed network features use Zeek. A pinned CICFlowMeter re-extraction and label-alignment pipeline would be required. Current download size and capture blocks have not been inventoried. | Higher-effort alternative if a broader environment shift is the priority. |

The official CIC-DDoS2019 page documents per-day PCAPs and CICFlowMeter-V3 CSVs. The user placed both official CSV archives in ignored `data/cicddos2019/`. Their verified inventory is:

| Archive | Compressed bytes | SHA-256 | CSV members | Uncompressed bytes | Rows |
| --- | ---: | --- | ---: | ---: | ---: |
| `CSV-01-12.zip` | 2,330,434,641 | `D5224F73B59F2BE783B620BC7046F4BF467C1FE226CFDBC036359AB40F32930D` | 11 | 22,310,877,833 | 50,063,112 |
| `CSV-03-11.zip` | 918,815,761 | `A81D8CE59A819D13E6BFEA4E4812D6D144D0572B6D2C42D8E0C0A8CF1C26C263` | 7 | 8,744,666,200 | 20,364,525 |

Every CSV has 88 columns. A full streaming row scan found 70,313,809 attack rows and 113,828 benign rows across the archives, with all rows matching an 88-field line count. `CSV-01-12.zip` timestamps are on 2018-12-01 and its rows contain 12 attack families (including 439 `WebDDoS` rows); `CSV-03-11.zip` timestamps are on 2018-11-03 and its rows contain seven families. The official page's prose says the training day has 12 attack types and the testing day seven, which agrees with the archives and server-IP day mapping in its machine table. The schedule table's “First Day” and “Second Day” headings are reversed relative to that mapping. Freeze the roles as `CSV-01-12.zip` / 2018-12-01 for calibration and `CSV-03-11.zip` / 2018-11-03 for final assessment. Use each row's `Label` field, not its member filename: several CSV members contain multiple labels. One 93-byte LibreOffice lock file is present in the second ZIP and is not a CSV member.

Observed label supports from the full scan:

| Raw label | 2018-12-01 calibration rows | Raw label | 2018-11-03 assessment rows |
| --- | ---: | --- | ---: |
| `BENIGN` | 56,863 | `BENIGN` | 56,965 |
| `UDP-lag` | 366,461 | `UDP` | 3,867,155 |
| `TFTP` | 20,082,580 | `UDPLag` | 1,873 |
| `Syn` | 1,582,289 | `Syn` | 4,891,500 |
| `DrDoS_UDP` | 3,134,645 | `MSSQL` | 5,787,453 |
| `DrDoS_SSDP` | 2,610,611 | `LDAP` | 1,915,122 |
| `DrDoS_SNMP` | 5,159,870 | `NetBIOS` | 3,657,497 |
| `DrDoS_NTP` | 1,202,642 | `Portmap` | 186,960 |
| `DrDoS_NetBIOS` | 4,093,279 |  |  |
| `DrDoS_MSSQL` | 4,522,492 |  |  |
| `DrDoS_LDAP` | 2,179,930 |  |  |
| `DrDoS_DNS` | 5,071,011 |  |  |
| `WebDDoS` | 439 |  |  |

The model expects 27 CICIDS2017 canonical features. All 27 are available in both archives after trimming header whitespace and applying four explicit aliases: `Total Fwd Packet` ← `Total Fwd Packets`; `Total Bwd packets` ← `Total Backward Packets`; `Total Length of Fwd Packet` ← `Total Length of Fwd Packets`; and `Total Length of Bwd Packet` ← `Total Length of Bwd Packets`. The trimmed 88-column headers are unique. No model outcomes have been calculated on these archives. [Dataset and day schedule](https://www.unb.ca/cic/datasets/ddos-2019.html) · [Official download portal](https://cicresearch.ca/CICDataset/CICDDoS2019/)

The CSE-CIC-IDS2018 page documents the available daily PCAP and CICFlowMeter-V3 features, while the TON_IoT page documents the PCAP/Zeek network formats and event ground truth. [CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html) · [TON_IoT](https://research.unsw.edu.au/projects/toniot-datasets)

## Provisional Experiment 007 protocol

1. Freeze the archive hashes, explicit date/role mapping, 27-feature alias map, binary label map (`BENIGN` versus every other nonempty label), class-family normalization, row policy, and streaming implementation before scoring any model.
2. Stream every row through the canonical 27-feature mapping. Record malformed data, exclusions, duplicate feature groups, cross-day overlap, and conflicting labels. Do not use labels to subsample. Keep the large source CSVs compressed and avoid materializing all rows in memory.
3. Use `CSV-01-12.zip` (2018-12-01; 12 attack families) only for threshold calibration. Apply one threshold per unchanged Experiment 006 model, maximizing attack recall subject to observed benign FPR <=1%. If no useful threshold exists, preserve the all-negative operating point and report it.
4. Freeze the selected thresholds, source hashes, block rules, label map, code hash, and report policy before scoring `CSV-03-11.zip` (2018-11-03; seven attack families). Do not revise the models or thresholds from those outcomes.
5. Report per normalized attack family and day: TP/FP/TN/FN, FPR, recall, precision, support, score quantiles, zero-score overlaps, and feature-vector collision/conflict counts. Compare the CIC-UNSW frozen thresholds and the newly calibrated thresholds descriptively. The 2018-11-03 archive alone determines the preregistered outcome.

This is a calibration-transfer study, not a new training comparison. It can show whether the frozen 2017 models support a useful threshold in a distinct capture system. A later weight change will require another protected capture after the Experiment 007 outcome is consumed.

## Acquisition gate

The two official CSV archives are present under ignored `data/cicddos2019/`; hashes, members, row totals, schema, label supports, and day mapping have been inspected. The streaming input adapter is `attack_traffic/experiment007_input.py` (SHA-256 `f66cd83c7f92ad086057bae23bafa8b8f3508a4cadb6420b55ca93fca8c58c92`). The full feature-quality and duplicate audit is complete at `artifacts/experiment-007-quality-audit/report.json`. All 70,427,637 rows passed the feature checks; there are 152,915 feature groups spanning both days and 669 binary-label-conflicting groups. All valid rows, including duplicates and conflicts, are retained for the primary analysis; these counts qualify its interpretation. Calibration completed and the four thresholds are frozen in `artifacts/experiment-007-calibration/thresholds.json`; the calibration protocol records audit, code, source policy and model hashes. The protected assessment is complete at `artifacts/experiment-007-assessment/report.json`; its interpretation and source hashes are documented in `docs/EXPERIMENT-007-ERROR-ANALYSIS.md`. Keep the archives compressed and do not substitute an unpinned source.
