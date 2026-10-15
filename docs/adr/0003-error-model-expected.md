# Error model: std::expected-style result with a three-flavour error type

Status: Accepted

Every Operation completes with `snmp_coro::Result<std::vector<Varbind>>`. SNMP failures are not exceptional: callers routinely need to tell "retry a timeout" apart from "the agent refused the value", and a thrown exception would force catch-blocks into normal control flow. Awaiting an Operation therefore never throws for an SNMP failure.

Exceptions are reserved for programmer errors, and they are thrown at the call site before anything is sent:

- `std::invalid_argument` for a malformed OID, invalid credentials, an unspecified target or out-of-range `Options`, an empty request, or a set varbind whose type and value disagree;
- `std::logic_error` for an Operation on a moved-from Session.

The project targets **C++20**, where `std::expected` does not exist, so `snmp_coro::Result<T>` is a type alias over `boost::system::result<T, snmp_coro::Error>`. Boost.System is header-only and already a dependency via Boost.Asio. Only the interface subset shared with `std::expected` is used, so upgrading to C++23 later is a one-line alias swap. `Result<T>::value()` on an error throws `snmp_coro::SnmpError`, which carries the `Error` (via the ADL hook `throw_exception_from_error`).

`snmp_coro::Error` holds:

- `code`: a `std::variant<TransportError, PduError, SecurityError>`. The active alternative *is* the glossary's error flavour (Transport error, PDU error-status, Security error). `flavour()` derives the `ErrorFlavour` from it, so the two can never disagree.
- `index`: the PDU error-index, or 0 when it does not apply.
- `message`: net-snmp's description.

Each code is the underlying net-snmp status translated into a scoped `enum class`, never a raw `SNMP_ERR_*`/`SNMPERR_*` int (ADR 0005). `PduError` values equal the RFC 3416 error-status codes.

Beyond the first sketch, `SecurityError` also has `notInTimeWindow`, `credentialConflict` (ADR 0006) and `unexpectedReport`, and `TransportError` has `limitExceeded`: a Walk that would collect more than `Options::maxWalkVarbinds` fails rather than growing memory without bound. One type for all three flavours keeps `co_await session.get(oids)` ergonomic while preserving the distinction that matters for retry logic.

A Walk that receives a non-increasing OID from the agent stops with `PduError::genErr`, rather than looping forever or silently truncating.
