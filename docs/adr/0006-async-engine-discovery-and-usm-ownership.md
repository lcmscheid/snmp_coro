# Asynchronous engine discovery, and a library-owned USM user table

Status: Accepted

Probing net-snmp 5.9.4 against a real `snmpd` turned up three behaviours that contradict ADR 0001 or are unsafe if left alone. Each was measured, and each now has a regression test.

## 1. net-snmp's "async" send can block

`snmp_sess_open` performs a synchronous engineID probe unless `SNMP_FLAGS_DONT_PROBE` is set. It then **clears that flag on its internal session copy**, after which `snmp_sess_async_send` runs a *synchronous* probe whenever the session has no engineID. Measured: the send blocks for `timeout × (retries + 1)`, which is 6 s with the default Options against a dead agent. Against a live agent it only looks asynchronous because the reply comes back within a millisecond.

**Decision.** Set `SNMP_FLAGS_DONT_PROBE` in the session config and **set it again on `snmp_sess_session(sessp)` after every open**. Do engineID discovery ourselves, asynchronously:

1. Open a throwaway noAuthNoPriv session with an empty user and send a GET (RFC 3414 §4).
2. The agent answers with a Report carrying its authoritative engineID.
3. Open the real session with `securityEngineID` set, so net-snmp never probes and localizes the keys at open.

The Session constructor does no I/O. Discovery starts on the first Operation, Operations submitted meanwhile are queued, and a failed discovery fails all of them. The next Operation retries discovery.

## 2. The USM user table is process-wide and silently reuses keys

net-snmp keeps one USM user table per process, keyed by (engineID, user name). A later session naming the same user reuses the cached entry's keys. Measured: once a Session with the correct passphrase had run, a Session with the **wrong passphrase authenticated successfully**.

**Decision.** The library owns that table through a registry keyed by (engineID, user), holding the protocols and master keys (Ku) of the live Sessions using each entry:

- With no live holder, any stale entry is deleted before the real session opens, so net-snmp creates it from this Session's keys.
- A live holder with the same keys shares the entry.
- A live holder with *different* keys makes the new Session's Operations fail with `SecurityError::credentialConflict`. The first live Session keeps working; the agent only accepts one passphrase anyway.
- When the last holder goes away the entry is deleted, so keys do not linger in net-snmp.

Limitation: other code in the same process that uses net-snmp directly shares that table.

## 3. Security failures are reported in two steps

A security failure produces a `RECEIVED_MESSAGE` callback carrying the Report PDU, followed by an `OP_SEC_ERROR` callback with no reason (`s_snmp_errno` is 0); this is the order in net-snmp 5.9.4's `_sess_process_packet_handle_pdu`. The library ignores the second and classifies the Report with `snmpv3_get_report_type`: `unknownUser`, `authFailure`, `unsupportedLevel`, `notInTimeWindow`, `discoveryFailed` for unknownEngineID, and `unexpectedReport` otherwise. If no Report arrives, the request times out normally, so an Operation can never hang.

A **wrong privacy passphrase** surfaces as `TransportError::timeout`, not `decryptFailed`. The agent's usmStatsDecryptionErrors Report is unauthenticated, and net-snmp discards it. `decryptFailed` exists for agents and paths where the Report is accepted.

A `notInTimeWindow` Report is the exception: net-snmp hands it to the callback and **then resends** the request with corrected time. Completing the Operation on that Report would fail it while net-snmp keeps retransmitting it, and a SET could still be applied. The library keeps the Report and completes with the outcome of the resend. If net-snmp is out of retries, it follows up with `OP_SEC_ERROR` and drops the request, and the Operation then fails with `notInTimeWindow`. Against snmpd 5.9.4 an agent restart did not take this path: the stale request timed out and net-snmp's retransmission succeeded. The handling follows the net-snmp source.

## 4. An engineID change looks like a timeout

The engineID is discovered once per Session. Measured: when the agent at the target is replaced by one with a different engineID, every later request **times out**. The new agent answers with an unknownEngineID Report, but net-snmp finds no USM user for (new engineID, user) and drops it (`usmStatsUnknownUserNames`). The Session would have failed forever, in a way indistinguishable from a dead agent.

**Decision.** A timeout, or an unknownEngineID Report should one arrive, marks the engineID as needing verification. Once no Operation is in flight on the session, the library closes it, releases the USM entry and runs discovery again for the queued Operations. Operations submitted meanwhile wait; Operations in flight are never failed to make this happen. The Operation that noticed the change still fails, with `TransportError::timeout` (or `SecurityError::discoveryFailed` for a Report): it was not processed by the agent, but the library does not resend on the caller's behalf.

Cost: after a timeout, the next Operation waits for one discovery round trip. Against a dead agent it fails with `TransportError::timeout` from discovery, as before.

## Consequences

- No net-snmp call made by the library blocks the io_context thread.
- An agent whose engineID changes (replaced, not merely rebooted) costs the Operations in flight at the time; later ones rediscover it (section 4). Reboots, which change engineBoots, are recovered within the Operation by net-snmp's retransmission.
