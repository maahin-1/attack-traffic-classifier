# Experiment 001: corrected-only preliminary baseline

Design frozen 2 November 2026 after inspecting dataset/schema/class inventories and before inspecting any model scores for this experiment.

Goal: establish a reproducible real-data baseline and reveal later-day generalization limits. This run cannot answer the original-versus-corrected comparison until the original timestamp-bearing export and shared feature policy are verified.

Snapshot: CNS2022 `CICIDS2017_improved.zip`, SHA-256 `97fdb91d339e2d8cf5627f981b831e5e7e400b981c58181c451a38fd03c48883`. Full inventory: 2,099,976 rows. No archive members were extracted; a label-independent hash sample of approximately 1% was sorted by event start and stored without endpoint identifiers.

Preparation: `data/cns2022/subset-1pct/preparation.json`. The selected population contains 20,909 rows. The audit retains 18,866 and quarantines 2,043 later feature duplicates; zero selected rows were excluded for required-feature quality. These are feature-equivalence groups, potentially including distinct flows and conflicting labels. No claim of independent unique network events is made.

| Partition | UTC period | Retained benign | Retained attacks |
| --- | --- | ---: | ---: |
| Train | Monday–Tuesday, 3–4 July 2017 | 6,837 | 74 |
| Validation | Wednesday, 5 July 2017 | 3,240 | 1,725 |
| Test | Thursday–Friday, 6–7 July 2017 | 5,678 | 1,312 |

Cutoffs: `2017-07-05T00:00:00+00:00` and `2017-07-06T00:00:00+00:00`. End times derive from starts plus microsecond Flow Duration. The sampled audit has sufficient binary support; class imbalance is retained in every partition. Test support was inspected as an inventory, without model scores, to expose unseen/absent classes.

Only FTP-Patator and SSH-Patator attacks occur in training. All sampled validation and test attack families are unseen during fitting. Some rare source families have no selected test examples; report their recall as unsupported. In particular, one sampled retained web-brute-force test record cannot justify a reliable class estimate.

Fixed configuration: 27 numeric duration, packet count/length and timing statistics declared in `attack_traffic/prepare.py`; 200 trees, depth 12, minimum leaf size 2, one CPU worker, seed 42, no weighting/resampling, identity preprocessing. A majority constant baseline uses the same partitions. A separate family forest is a closed-set attribution diagnostic.

Threshold policy: maximize validation binary attack recall under observed benign FPR <=1%; ties prefer fewer alerts, then higher threshold. Record infeasible useful detection rather than relaxing the ceiling. Freeze this threshold before scoring test. No hyperparameter grid or test-driven iteration in this experiment.

Primary evidence: confusion counts, FPR/recall/precision, average precision, pooled precision@100 with stable-ID ties, Wilson intervals, per-family training/test support, unseen-attack detection recall, row accounting, wall time and process peak memory. Wilson intervals assume independent flows; no temporal-block comparison uncertainty is available in this first run. Pooled precision@100 is not an estimate of daily alert capacity.

Known limits: corrected-only sampled population, no vetted original feature intersection, sparse rare classes, attempted→benign target policy, capture bias, conservative feature deduplication and correlation between flows. Corrected redistribution terms remain unverified; the acquired files stay local and untracked.

Run command after preparation:

```powershell
python main.py run --config data/cns2022/subset-1pct/config.json
```

Output: `artifacts/corrected-subset-1pct/`. Results are recorded after the design above; no changes to this design may be justified from its test metrics.

## Observed results

The frozen random-forest threshold is 0.01375. Validation detects 51 of 1,725 attacks (**2.96% recall**) with 16 false positives among 3,240 benign flows (**0.494% FPR**). Test detects 946 of 1,312 attacks (**72.10% recall**) with 30 false positives among 5,678 benign flows (**0.528% FPR**). Test precision is 96.93%, pooled precision@100 is 95%, and average precision is 0.76465. The constant baseline detects no attacks at the permitted operating point.

The high test aggregate masks weak generalization. DDoS contributes **940 of the 946 detected attacks**; its test recall is 940/940. Portscan recall is **1/95**, infiltration-portscan **2/269**, and Botnet **2/7**. The single web-brute-force record is detected but is insufficient evidence about that family. Excluding DDoS, only 6 of 372 test attacks are detected. Family attribution recall is zero for unseen test attack families, as expected for a model trained only on FTP/SSH families. No threshold or model setting was changed after observing these outcomes.

Wilson 95% test intervals are approximately **0.370–0.753% FPR** and **69.62–74.46% recall**, under the stated flow-independence assumption. They do not capture temporal dependence or uncertainty from this particular sample/release.

Measured audit/training/evaluation pipeline time was **4.800 seconds**, excluding package import/startup, acquisition, full ZIP inventory and subset preparation. Windows process lifetime peak working set was **216,944,640 bytes** (about 206.9 MiB). This measurement applies only to this configured subset on this machine, with one worker.

The saved-model `score` command reproduced all **6,990 test rows** with zero absolute score difference and identical threshold decisions and family predictions. Evidence: `artifacts/corrected-subset-scorecheck.json`. The full software suite passed **53 tests**.

Interpretation: this is a functioning baseline with a strong attack-family shift, not a broadly effective detector. The next experiment should first complete the original-data contract and matched settings, then compare per-family behavior and population losses. Test outcomes here must not be used to retune this run and claim an independent test result.

## Saved-score review exports

The same frozen experiment can now be regenerated with `python main.py report --run artifacts/corrected-subset-1pct --output artifacts/research-report --charts --parquet`. This verifies the recorded evidence and adds class-recall/confusion charts and split/prediction Parquet exports without fitting or loading models. The original thresholds and test scores remain unchanged. The report explicitly withholds a paired comparison while original data are unavailable.

All 20,909 split rows and 23,910 validation/test prediction rows (two models) were round-trip checked through Parquet with every value preserved; source input artifacts stayed byte-identical. Verification evidence is in `artifacts/report-verification.json`. The current full suite passes 71 tests; the earlier 53-test statement above records the original baseline implementation checkpoint.
