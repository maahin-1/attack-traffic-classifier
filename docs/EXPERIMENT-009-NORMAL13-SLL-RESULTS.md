# TON_IoT normal13 cooked-header investigation

## What was verified

The full `normal_13.pcap` development capture was reread with [a declared aggregate-only plan](EXPERIMENT-009-NORMAL13-SLL-PLAN.md). The scan reproduced **1,918,446 packets**, including **1,599,685** with Linux cooked v1 protocol field `0x0003`. Every `0x0003` frame had cooked packet type 4, hardware type 1, and address length 6; the recorded captured and original lengths were equal for those frames. Equal lengths do not prove that the capture contains all traffic or that earlier capture stages retained every byte.

Libpcap identifies cooked packet type 4 as outgoing, while the Linux header defines hardware type 1 as Ethernet and protocol value `0x0003` as `ETH_P_ALL`, a catch-all value rather than an identified network-layer protocol. Sources: [libpcap cooked header](https://github.com/the-tcpdump-group/libpcap/blob/master/pcap/sll.h), [Linux hardware types](https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_arp.h), [Linux protocol constants](https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_ether.h).

In a systematic file-order sample of **9,998** `0x0003` frames (every 160th), all began with a zero first payload nibble. None passed either a basic Ethernet-type heuristic or a search for a checksum-valid IPv4 TCP/UDP header at offsets 0–64 after the cooked header. These are bounded heuristics, not proof that the frames do not contain IP packets. In particular, checksum offload, truncation at an earlier source, uncommon encapsulation and untested offsets may affect the result.

An upstream [libpcap issue](https://github.com/the-tcpdump-group/libpcap/issues/739) reports separate cases where cooked packets marked `0x0003` had ambiguous encapsulation. That establishes a relevant possibility, not that the same bug caused this capture's values. We have **not identified the encapsulation or recovered those frames**. They remain excluded from the project's current IPv4 TCP/UDP decoder; there is no speculative rewrite. The experiment has not established the direction distribution of the other protocol values or the true packet-loss rate.

## Verification

The [machine-readable report](../artifacts/experiment-009-normal13-sll/report.json) has SHA-256 `71f3c3b18752123e0a2560c8a2dfa1ec4358a8d4dbfeb62669e60b43a5e87d24`. The local capture's SHA-256 was checked before, during and after the full read; dependency hashes and original inventory totals were checked. Two focused tests verify the IPv4 header-checksum heuristic and short-input handling. Source endpoints and payloads were not exported. These local checks do not authenticate publisher provenance.

## Labeling implication

The source's `normal_pcaps` folder is a **source claim**, not independent per-flow confirmation. Neither this header inspection nor the other inspected scanning-event CSV proves that this capture is attack-free or that all attack events are recorded. The publisher's [TON_IoT page](https://research.unsw.edu.au/projects/toniot-datasets) describes event labeling using attacker addresses and timestamps; it does not establish per-file benign coverage or a complete flow-level mapping for this particular capture. Its network feature-description preview identifies Zeek connection fields but does not identify the unknown encapsulation or establish the crosswalk to this project's 27 features.

The resulting [development label policy](EXPERIMENT-009-DEVELOPMENT-LABEL-POLICY.md) therefore retains `normal_13` as **unverified/unknown** until independent capture and event-coverage evidence supports a narrower label. Do not infer benign from an event-log nonmatch, from a protocol, or from `0x0003`. No model was trained, calibrated or scored; no final holdout was selected.
