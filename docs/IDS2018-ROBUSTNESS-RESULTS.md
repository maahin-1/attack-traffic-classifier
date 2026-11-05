# CSE-CIC-IDS2018 cross-version robustness results

The fixed [protocol](IDS2018-ROBUSTNESS-PROTOCOL.md) was run on 15 and 16 February 2018 using the previously frozen 2017 binary models and thresholds. This assesses agreement with the source's supplied labels across separate research captures and potentially different feature-extraction versions. It does not demonstrate operational-network performance, verified labels or equivalent flow-meter behavior. Both models exceed the 1% false-positive target on 15 February.

| 2017 training variant | 2018 day | Attack recall | Benign false-positive rate | Precision | TP / attacks | FP / benign |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Original | 15 Feb | 6.52% | 7.25% | 4.52% | 3,421 / 52,498 | 72,245 / 996,077 |
| Original | 16 Feb | 23.26% | 0.47% | 98.53% | 139,991 / 601,802 | 2,092 / 446,772 |
| Corrected | 15 Feb | 20.96% | 5.56% | 16.58% | 11,006 / 52,498 | 55,378 / 996,077 |
| Corrected | 16 Feb | 0.0023% | 0.092% | 3.28% | 14 / 601,802 | 413 / 446,772 |

Attack-family results differ sharply. The original-data model flagged all 139,890 flows labeled SlowHTTPTest on 16 February but only 101 of 461,912 labeled Hulk; the corrected-data model flagged none of the SlowHTTPTest flows and 14 Hulk flows. Published [dataset correction research](https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html) reports problems with some source attack scenarios, including SlowHTTPTest, so these counts cannot be taken as confirmed real-attack detection. On 15 February the models flagged 148/41,508 and 8,391/41,508 GoldenEye-labeled flows, respectively; source-label limitations also apply.

Of 2,097,150 CSV records, one repeated header was excluded; 2,097,149 were scored per model. On 15 and 16 February, respectively, 113,993 and 156,995 eligible feature vectors matched a frozen 2017 feature-group hash. They were retained as planned: matching a 27-feature projection does not establish shared flow identity. The [publisher's 2017](https://www.unb.ca/cic/datasets/ids-2017.html) and [2018](https://www.unb.ca/cic/datasets/ids-2018.html) schedules support distinct capture dates, but both days are dependent blocks of a generated environment. No reliable temporal-block interval is claimed from two days.

Both files contain exactly 1,048,575 records after their header. This unusual identical size warrants further investigation of source capture coverage; it is not by itself proof of truncation.

The full machine-readable metrics, label slices, row exclusions, model and source hashes are in `artifacts/ids2018-cross-version-evaluation/`. Input, protocol, model and code hashes were recorded locally in `artifacts/ids2018-prescore-commitment-v2.json` before the completed run. This local record is not an independently timestamped or authenticated preregistration. A previous run was interrupted before publishing results to tighten the verification checks; no result from it was used. No thresholds or models were changed after reading these outcomes. Any further model development informed by these results requires another independent assessment.
