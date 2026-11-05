# Experiment 007: high-volume feature-group investigation

## Scope and verification

This is a descriptive investigation on the already consumed 2018-11-03 assessment. Groups were selected after seeing the assessment: the five with the most attack-labeled assessment rows and the five binary-label-conflicting groups with the most total assessment rows, breaking ties by digest. One group appears in both lists, leaving nine distinct groups. They are deliberately high-volume examples, not a random or representative sample. The selection and source/model fingerprints were recorded before this trace. No model or threshold was changed.

The runner scanned all 20,364,525 assessment rows. For every selected group, its observed assessment benign and attack counts reproduced the independently saved group audit. The archive, audit database, audit report, adapter, frozen thresholds, model bundles and investigation runner were hashed before and after the scan. The aggregate result is `artifacts/experiment-007-group-investigation/report.json` (SHA-256 `e33e39087e470e82c9d09cd769849c5eff78c3bd1fd4819a4e23e4082e530ea3`); `protocol.json` records the exact selection and fingerprints. The report includes per-label source members, timestamp ranges, protocols, destination-port frequencies, the 27-feature vector, and scores at both frozen thresholds. Endpoint addresses were not copied into the report.

Each digest represents equality of the 27 model features after canonical numeric conversion; it is not a raw flow identity. CSV timestamps are presented in the dataset's clock, whose timezone is not established here.

## Why row-weighted recall is concentrated

The five largest attack-labeled feature groups contain **6,246,211 of 20,307,560 attack rows (30.758%)**. The original reference model at its previously frozen Experiment 006 threshold flags four of them:

| Feature digest prefix | Attack rows | Main source labels | Reference score | Reference alerts? |
| --- | ---: | --- | ---: | --- |
| `b394ec7e0f15` | 2,173,449 | NetBIOS 2,058,914; Portmap 114,523 | 0.044306 | Yes |
| `7f6878da00b2` | 1,812,610 | SYN 1,812,590 | 0.021510 | No |
| `51cae115fb68` | 1,422,393 | LDAP 1,375,791; MSSQL 46,602 | 0.041925 | Yes |
| `e08d87ada59d` | 427,723 | UDP 409,504; MSSQL 18,219 | 0.044306 | Yes |
| `353471bc1804` | 410,036 | UDP 410,036 | 0.044306 | Yes |

The four detected groups contribute **4,433,601 of the model's 10,299,492 assessment true positives (43.047%)**. They are four distinct 27-feature vectors, all found on protocol-17 rows in the source. Each describes two forward packets, no backward packets, and a 1-microsecond flow duration; their packet lengths differ. They also occur on the calibration day. This concentration explains a substantial part of the gap between 50.718% row-weighted recall and 0.276% group-label-weighted recall. It does not establish how frequently these patterns occur outside this dataset.

The missed `7f6878da00b2` group has 1,812,590 SYN-labeled rows: **37.056% of all 4,891,500 SYN-labeled assessment rows**. Its 27 features include two forward packets, no backward packets, 12 total forward bytes and a 1-microsecond duration. The original reference score is 0.021510, below its 0.038333 threshold. The corrected candidate scores it 0.351071 and flags it at both its old and newly calibrated thresholds, but that candidate's overall benign FPR fails the 1% limit on this capture.

## Conflicting labels in context

The five largest conflicting groups contain 2,512,198 attack-labeled and 2,086 benign-labeled assessment rows. All five are protocol-6 in the source and all are below the original reference's prior and recalibrated thresholds. Their SYN-labeled rows total 2,512,169, or 51.358% of the assessment's SYN-labeled rows. The original reference consequently misses all attack-labeled rows in these five groups.

The largest conflict, `7f6878da00b2`, contains 1,812,610 attack-labeled and 673 benign-labeled assessment rows. For example, a benign row occurs in `03-11/LDAP.csv` at dataset-clock time `10:09:00.744475`, destination port 80, while a SYN-labeled row occurs in `03-11/Syn.csv` at `11:36:28.607388`, destination port 33827. Both are protocol 6 and have the same 27-feature digest. The SYN-labeled rows in this group span `11:29:17.786188`–`11:37:17.777691`; benign-labeled rows span `09:18:55.045152`–`17:16:40.471518`. The publisher's [dataset description and schedule](https://www.unb.ca/cic/datasets/ddos-2019.html) describe labels using timestamps, IPs, ports and protocol and list SYN activity from 11:28 to 17:35 in the seven-family schedule. The page's day headings conflict with its prose, as documented in the discovery note. These observations are consistent with different capture contexts sharing the same model inputs; they do not establish which individual label is correct.

The 27-feature model does not consume source/destination addresses, ports, protocol, timestamps, or TCP flags. Different ports and times can therefore coexist in one feature group. Adding context or flags could help distinguish some patterns, but their semantics, availability at prediction time, and potential capture-environment shortcuts require separate development-data investigation. TCP protocol alone would not distinguish the benign and SYN examples above because both have protocol 6. Timestamp or endpoint memorization should not be assumed to transfer to a new network.

## A constraint within this capture

The assessment has 56,965 benign rows, so a deterministic classifier with observed FPR at most 1% can flag at most **569** benign rows. The largest conflicting group alone contains **673 benign rows** (1.181% of the benign support). Any deterministic classifier using only these 27 features must assign all rows in that group the same decision. Flagging the group would exceed the observed FPR budget; not flagging it misses its 1,812,610 attack-labeled rows, or 8.926% of assessment attacks. Under these labels and this row-weighted evaluation, that one group alone limits recall to at most **91.074%** while meeting the 1% FPR constraint; other conflicts can impose tighter limits. This is a mathematical property of the assessed feature projection and labels, not a claim about any other network or about which source labels are correct.

## Next work

1. Inspect packet or independent event context for selected conflicts where it is available; document whether labels can actually be adjudicated. Keep uncertainty when the available context is insufficient.
2. Use separate development data to evaluate additional semantically justified features, such as properly available TCP-flag or protocol information, and assess whether they reduce feature-group conflicts without relying on environment-specific identifiers.
3. Freeze any resulting model and threshold before evaluation on a new independent capture. Report row-weighted and group-aware results, benign FPR, and per-family recall. The present assessment and these selected examples are consumed development evidence for subsequent choices.
