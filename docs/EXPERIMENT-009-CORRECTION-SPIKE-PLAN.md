# Experiment 009: scoped standard-deviation correction spike

Java is not currently on PATH; Docker CLI reports no running engine and WSL
listing reports access denied. Do not install a runtime or modify system setup.
Use the previously verified pycicflowmeter source archive at commit
`4432a32e05491c110f78fe80a59ab733b145d2cb`. Create an isolated copy under the
test directory and replace **only** the two forward/backward packet payload
length `statistics.pstdev` calculations with `statistics.stdev` for two or
more samples and zero otherwise. Capture the exact source diff and hashes.
This is a disposable research variant, not a release or a Java implementation.

Run both original and variant with identical offline CLI settings (120-second
flow timeout; five-second activity timeout) and synthetic PCAPs only:

* directional payloads forward [4, 8] and backward [3, 9], with whole-flow
  gaps of 1, 2 and 1 seconds: expected corrected packet standard deviations
  sqrt(8) and sqrt(18), respectively; IAT sample std sqrt(1/3) million µs;
* a reverse-first UDP flow: the first packet establishes forward direction;
* activity gaps below, at and above five seconds, plus a subsequent packet;
* same-flow packets at 119.999999, 120.000000 and 120.000001 seconds, each
  in a separate case, to observe timeout boundaries (including singleton
  handling). Do not assert Java parity without running it;
* TCP ACK, FIN and reverse FIN, followed by ACK to observe termination;
* single-packet UDP and equivalent Ethernet/Linux-cooked TCP cases retained
  from prior fixture tests, for regression.

Record all rows and CLI errors; compare all 27 model fields and identities
between variants, preserving fixture and source hashes and the plan hash.
Any differences beyond the two targeted fields are unexpected and require
investigation. Do not score captures or infer real-data model performance.
