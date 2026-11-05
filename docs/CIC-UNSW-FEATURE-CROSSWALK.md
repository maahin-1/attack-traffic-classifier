# CIC-UNSW-NB15 feature crosswalk for Experiment 006

## Scope and evidence

UNB says `CICFlowMeter_out.csv` contains the CICFlowMeter-extracted flow population before its separate benign down-sampling step. UNB also describes matching extracted flows to the UNSW ground-truth records by the five-tuple, resolving multiple candidates by timestamp, dropping unresolved ambiguous flows, and assigning remaining unmatched flows to benign. This supports the table's field names and label provenance. It does not identify the exact CICFlowMeter commit, build settings, or timestamp timezone used for the pinned mirror file.

The CICFlowMeter project's `FlowFeature.java` declares the exact source column names present in the file. Its `BasicFlow.java` contains the feature calculation implementation. The project's feature documentation describes flow duration and inter-arrival features in microseconds, packet-length and total-length features in bytes, and packet totals as counts. This is a semantic crosswalk to the documented CICFlowMeter implementation. Because the archive-producing revision is unknown, it does not prove that every implementation detail matches this particular archive. The source timestamps are therefore grouped by their literal clock dates without timezone conversion.

Sources: [UNB CIC-UNSW-NB15 dataset description](https://www.unb.ca/cic/datasets/cic-unsw-nb15.html), [CICFlowMeter feature names](https://github.com/ahlashkari/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/FlowFeature.java), [CICFlowMeter calculations](https://github.com/ahlashkari/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java), [CICFlowMeter feature descriptions](https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt).

## Canonical model inputs

| Canonical feature | CIC-UNSW column | Meaning | Unit |
| --- | --- | --- | --- |
| `flow_duration` | `Flow Duration` | Duration of the bidirectional flow | microseconds |
| `total_fwd_packets` | `Total Fwd Packet` | Packet count in the forward direction | packets |
| `total_bwd_packets` | `Total Bwd packets` | Packet count in the backward direction | packets |
| `total_fwd_bytes` | `Total Length of Fwd Packet` | Sum of forward packet lengths | bytes |
| `total_bwd_bytes` | `Total Length of Bwd Packet` | Sum of backward packet lengths | bytes |
| `fwd_packet_length_max` | `Fwd Packet Length Max` | Maximum forward packet length | bytes |
| `fwd_packet_length_min` | `Fwd Packet Length Min` | Minimum forward packet length | bytes |
| `fwd_packet_length_mean` | `Fwd Packet Length Mean` | Mean forward packet length | bytes |
| `fwd_packet_length_std` | `Fwd Packet Length Std` | Standard deviation of forward packet lengths | bytes |
| `bwd_packet_length_max` | `Bwd Packet Length Max` | Maximum backward packet length | bytes |
| `bwd_packet_length_min` | `Bwd Packet Length Min` | Minimum backward packet length | bytes |
| `bwd_packet_length_mean` | `Bwd Packet Length Mean` | Mean backward packet length | bytes |
| `bwd_packet_length_std` | `Bwd Packet Length Std` | Standard deviation of backward packet lengths | bytes |
| `flow_iat_mean` | `Flow IAT Mean` | Mean inter-arrival time across flow packets | microseconds |
| `flow_iat_std` | `Flow IAT Std` | Standard deviation of flow inter-arrival times | microseconds |
| `flow_iat_max` | `Flow IAT Max` | Maximum flow inter-arrival time | microseconds |
| `flow_iat_min` | `Flow IAT Min` | Minimum flow inter-arrival time | microseconds |
| `fwd_iat_total` | `Fwd IAT Total` | Total forward-direction inter-arrival time | microseconds |
| `bwd_iat_total` | `Bwd IAT Total` | Total backward-direction inter-arrival time | microseconds |
| `active_mean` | `Active Mean` | Mean duration of active periods | microseconds |
| `active_std` | `Active Std` | Standard deviation of active-period durations | microseconds |
| `active_max` | `Active Max` | Maximum active-period duration | microseconds |
| `active_min` | `Active Min` | Minimum active-period duration | microseconds |
| `idle_mean` | `Idle Mean` | Mean duration of idle periods | microseconds |
| `idle_std` | `Idle Std` | Standard deviation of idle-period durations | microseconds |
| `idle_max` | `Idle Max` | Maximum idle-period duration | microseconds |
| `idle_min` | `Idle Min` | Minimum idle-period duration | microseconds |

## Assessment boundary

The pinned mirror file passed the row-width, finite-value, nonnegative-duration, timestamp parsing, source-hash, and official label-total checks recorded in `artifacts/cic-unsw-nb15-mirror-inventory.json`. This evidence supports running the preregistered research comparison against this pinned artifact with the qualifications above. It does not authenticate that the mirror bytes are identical to UNB's current publisher copy. The file is not used to select features, models, thresholds, mappings, or exclusions.

Experiment 006 groups 22 January as one source-clock block and pools 17–18 February as a second block. This avoids pretending that two adjacent dates are independent captures when the session boundary is undocumented. Flow-level intervals will not be interpreted as independent-session uncertainty.
