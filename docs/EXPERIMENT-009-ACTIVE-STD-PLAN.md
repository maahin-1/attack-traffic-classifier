# Experiment 009: experimental active/idle sample standard deviation

Make a new disposable copy of the previously hashed SYN-ACK-fixed extractor.
In both `flow.py` and `analyzer.py`, replace population standard deviations of
active and idle duration arrays with sample standard deviation when there are
at least two values, or zero otherwise. Preserve all other code, the original
source and prior variants. Save the full upstream-to-variant patch and hashes.
This implements the explicitly chosen synthetic research contract; it does not
claim the Java runtime or historical training extractor had identical behavior.

Run the original seven synthetic feature-boundary PCAPs with the new variant,
comparing with the saved, hashed prior-variant outputs. The new variant must give active std 1,000,000 µs and idle std
sqrt(2)*1,000,000 µs on the preregistered variance fixture. Differences in
all cases must be confined to Active Std and Idle Std fields, with no flow
count changes. Run the earlier thirteen synthetic direction/boundary fixtures
as a regression comparison and apply the same difference restriction. Record
hashes, all outputs and errors, and verify expected sample values independently.
Out-of-order and fragmented cases are included solely to compare calculations;
preflight would reject them, and no real data or model scores are authorized.
