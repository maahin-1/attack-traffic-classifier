# Experiment 009: preliminary development label policy

Status: **conservative design and exclusion policy, not a frozen assessment protocol**. It governs the already-consumed TON_IoT development files. The event-to-packet checks were post-hoc, and no complete source event ledger or verified packet-to-flow extractor has been established.

| State | Minimum evidence | Use |
| --- | --- | --- |
| `attack_candidate` | A source event and a packet/flow agree under a separately specified time, protocol, direction and tuple policy; record match ambiguity, provenance and source attack type. | Exploratory development only, with source uncertainty retained. A packet-level match does not itself establish a full flow label. |
| `normal_source_claim` | Publisher provides explicit normal-capture provenance for a defined capture/time scope. | Keep as weak source metadata. It is not automatically equivalent to verified benign ground truth and cannot alone justify a final FPR estimate. |
| `benign_verified_for_protocol` | A predeclared protocol establishes applicable source provenance, documented normal collection window, complete-enough event coverage for that scope, unambiguous flow boundaries, time alignment, and absence of known attack overlaps. Preserve evidence and exclusions. | Eligible only within that protocol; uncertainty and session dependence remain. No current `normal_13` flows have this status. |
| `unknown_or_ambiguous` | Missing/incomplete event coverage, unclear flow boundaries, clock uncertainty, tuple reuse, conflicting evidence, unsupported encapsulation or an event-log nonmatch. | Exclude from supervised binary labels and any FPR denominator until a predeclared policy resolves the evidence. Do not silently map to benign. |

## Current decisions

1. Keep `normal_13.pcap` as source-claimed normal but **unverified/unknown** for supervised benign labeling. Its `0x0003` frames also remain undecoded.
2. `GroundTruth_Network_1.csv` and scanning1/scanning6 are development sources already inspected. Their selected packet/event comparisons support timing hypotheses, not a validated complete flow-label join or a new holdout.
3. Use endpoint and timestamp information only for provenance and permitted label alignment, never as input features. Store raw endpoint-level data only in excluded local data/artifact directories.
4. Before implementing a production data adapter, define a pinned extractor, flow timeouts and direction, session groups, exact event/flow matching and time uncertainty, handling of tuple reuse and mixed or boundary-crossing flows, plus complete row accounting. Validate with synthetic fixtures and separate development examples. Freeze these decisions and ambiguity exclusions before an independent final assessment.
5. Do not compute FPR until the denominator and its labels are supported for the evaluated time and population. Report source claims, excluded/unknown support, block dependence, and confidence limitations.

No model, threshold, capture role beyond development, or corrected TCP-flag mapping is changed by this policy. The final independent holdout remains unselected.
