# Experiment 009: feature and capture boundary characterization

Use only the previously hashed third experimental Python variant from
`artifacts/experiment-009-synack-fix/protocol.json`, offline and without real
captures. Save source/fixture/runner/plan hashes, dependency versions, input
packet readback, CLI outputs, full rows, and errors. This is not Java parity.

Preregistered independent reference for the active/idle fixture: six forward
UDP packets at relative seconds [0, 1, 7, 9, 17, 20], activity threshold 5 s.
Under an interval model where gaps greater than 5 s close an active interval,
active durations are [1, 2, 3] s and idle durations [6, 8] s. Mean, min, max,
and sample standard deviations are respectively active [2, 1, 3, 1] s and
idle [7, 6, 8, sqrt(2)] s (report in microseconds). This is an explicit
research contract, not a claim that the training CSV used those semantics.

Additional cases: the exact 5-second activity threshold; equal packet
timestamps; an out-of-order timestamp; an RST packet between an ACK and a
following packet; and a UDP packet fragmented at IPv4 level alongside the
same unfragmented datagram. Compare basic input/output counts, direction and
time, note warnings and unsupported fragments, and do not assume packet-based
or datagram-based conventions are universally correct. Separately inspect the
previously saved 120-second timeout cases. Do not fix an outcome mid-run or use
assessment data; retain discrepancies for a separately specified follow-up.
