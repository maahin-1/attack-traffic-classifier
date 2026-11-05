# Experiment 007 descriptive sensitivity analysis

This analysis was specified after the original assessment was consumed. It describes the already observed capture and cannot serve as an independent confirmation or a basis for retuning. Reuse all four frozen models and both frozen threshold sets exactly as recorded; do not select new thresholds.

An exact feature group is the SHA-256 digest of the canonical 27 numerical features, using the existing `feature_digest` representation. Binary conflict means a group has at least one benign and one attack row across the two source archives. Feature equality does not establish flow identity or which label is correct.

Report three measures for each model and threshold, using assessment rows only:

1. **Original row weighting:** count every valid assessment row, including duplicate and conflicting groups. The reconstructed confusion counts must exactly match the frozen assessment report.
2. **Group-label weighting:** give one unit to each distinct `(feature digest, binary label)` pair present in the assessment. Thus a group with both assessment labels contributes one benign and one attack unit, avoiding an arbitrary majority-label decision. This is not a count of independent flows.
3. **Conflict-excluded row weighting:** remove all assessment rows whose feature group contains both binary labels anywhere across the calibration and assessment archives; otherwise retain the original row weights. Report excluded rows and resulting supports. This is descriptive and may introduce selection bias.

Use the audit's per-group assessment benign/attack counts as row weights, and score one representative vector for each observed group-label pair. Verify the source archives and frozen hashes, audit table totals, the complete assessment row count, and exact reproduction of the original confusion counts. Record protocol, code, audit database, model, and threshold hashes before scoring. Report recall, FPR, precision, supports, and confusion counts; skip family metrics because binary group-label pairs may contain multiple attack families. No threshold or model changes are permitted.
