# SNMP Coroutine

An async C++20 library wrapping net-snmp's manager side (get, getNext, getBulk, set) as Boost.Asio asynchronous operations usable with any completion token, including C++20 coroutines. It is scoped to SNMPv3 with USM authentication (MD5, SHA-1, SHA-2) and privacy (DES, AES-128).

## Language

**Session**:
A long-lived handle to one SNMPv3 agent under one set of USM credentials. Many in-flight Operations are multiplexed over one Session. Created once, destroyed via RAII; destroying it aborts its in-flight Operations.
_Avoid_: connection, socket

**Operation**:
One SNMP request/response exchange: a get, getNext, getBulk, or set. An Operation ends in a result or in one of the three error flavours below.
_Avoid_: command, call, query

**Walk**:
Repeated getBulk Operations starting at a root OID, collecting every varbind in the subtree strictly beneath it. A helper composed from Operations, not a wire Operation.
_Avoid_: crawl, traverse

**Engine discovery**:
Learning the agent's authoritative engineID, which USM needs before it can authenticate. It happens asynchronously on a Session's first Operation, by sending an unauthenticated probe whose Report carries the engineID. It runs again after a timeout, in case the agent was replaced.
_Avoid_: handshake, connect

## Error flavours

**Transport error**:
An Operation failed at the socket level, timed out after all retries, or was aborted (cancelled, or its Session destroyed); or a Walk exceeded its client-side size limit. The agent never produced a usable response.
_Avoid_: network failure, connectivity issue

**PDU error-status**:
The agent answered, but the response PDU carries an error-status (`noSuchName`, `genErr`, `wrongValue`, …). The request was understood and refused. A missing object in a get is *not* an error: it comes back as a `NoSuch` value (`noSuchObject`, `noSuchInstance`, `endOfMibView`).
_Avoid_: SNMP exception, agent error

**Security error**:
A USM-level failure: an unknown user, wrong keys, an unsupported security level, failed engine discovery, a Report from the agent, or a credential conflict. A credential conflict means another live Session in the process already uses different keys for the same user on the same engine.
_Avoid_: auth failure (ambiguous with PDU error-status)
