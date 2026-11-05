# Experiment 009: TON_IoT holdout feasibility

Status: **candidate only; no assessment capture has been selected or reserved**. This inventory was prepared before inspecting any TON_IoT traffic, attack labels, feature values or model results. The previously evaluated CIC-DDoS2019 and CIC-UNSW captures remain consumed.

Subsequent update: the user opened the official listing and supplied a README plus one ground-truth CSV for **development-only** inspection. See [development metadata inventory](EXPERIMENT-009-TON-IOT-DEVELOPMENT-INVENTORY.md); at that point no PCAP or final holdout had been acquired or reserved.

Further update: the user subsequently supplied a scanning ZIP. Two member captures have now been examined as development material; [the scanning probe](EXPERIMENT-009-SCANNING-PROBE-RESULTS.md) finds partial same-second event-to-packet agreement for one member. No final holdout has been reserved.

## Source and access

The [UNSW TON_IoT project page](https://research.unsw.edu.au/projects/toniot-datasets) describes a separate IoT/IIoT lab with network PCAPs, Zeek logs and CSVs, as well as event information using attacker addresses and timestamps. This is a different testbed from the project's CICIDS2017 training capture, but it is still a laboratory environment, not independent evidence of enterprise performance. The published feature CSVs are Zeek-derived and cannot be assumed to match our CICFlowMeter-based 27-feature contract.

On 5 November 2026, the dataset link on that official page redirected an unauthenticated web inspection to a Microsoft sign-in page. This shows the observed access path, not that every user is unable to access the files. The page does not list the individual network capture filenames, file sizes, checksums, capture periods, independent session boundaries or label-to-PCAP alignment. No transfer or registration was performed; none of these unknowns is inferred. An [Australian research-data record](https://researchdata.edu.au/new-generations-internet-toniot-datasets/1957406) corroborates the dataset identifier but did not provide a verified current file listing in this inspection.

The UNSW page states academic-research use is free, requires citation of the listed papers, and says commercial use requires asking the author. It does not establish permission to redistribute the raw data or derived records. The project MIT license applies to project-authored code, not to TON_IoT data or third-party tools.

## Current local capabilities

On this Windows machine, the Docker client was found but its Linux engine was not reachable at inspection; `java`, `tshark` and `cicflowmeter` were not found on `PATH`. The active Python installation did not contain `scapy`, `dpkt` or `cicflowmeter`. These are environment observations, not proof that no equivalent tool exists elsewhere on the computer. D: reported approximately 399 GiB free; usable space and dataset transfer/extraction sizes must be rechecked at acquisition time. No software was installed and no global or Docker settings were changed.

## Gates before declaring an untouched holdout

1. Obtain an official, accessible inventory: exact filenames, sizes and checksums if supplied; capture/session timing and identity; record format; attack and benign coverage; and any overlap among files. Verify access and terms without ingesting holdout model scores.
2. Select and record exact final holdout units and protected data paths before development on their contents. Preserve whole independent capture sessions or environments where possible, not random rows. A dataset or day alone does not guarantee independence. Reserve separate development and calibration sources; do not calibrate on the final holdout.
3. Pin a flow-extraction tool, build, flow timeout, direction rules, feature definitions and versions. Prove the extraction contract with project-owned synthetic packet fixtures and separate development captures, including field units and edge cases. Apply the same frozen extraction process to development and holdout PCAPs; do not equate Zeek CSV columns with CICFlowMeter columns by name.
4. Predefine source-label alignment from the publisher's events to extracted flows, including timezone, protocol and direction, interval overlap, ambiguous flows, missing logs and unmatched traffic. Treat source labels as imperfect. Do not use identifiers or event labels as model inputs. Freeze ambiguity exclusions before final evaluation.
5. Record archive and tool hashes, split membership, label policy, model-selection rule, calibration procedure, threshold and report metrics before final scoring. Enforce disjoint development/calibration/holdout captures and report any verified overlap without selecting based on the holdout's model outcomes.

Only after these gates can TON_IoT be called a prospective independent assessment for the stated experiment. If official access or label/feature alignment cannot be established, record the blocker and evaluate another source instead of silently substituting a mirror.
