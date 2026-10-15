# Token-generic Operations: async_initiate at the boundary, co_composed for composition

Status: Accepted

## Context

The first interface sketch returned `asio::awaitable<Result<...>>`, which only works inside `co_spawn`ed coroutines. Asio's lightweight-coroutine technique (`co_composed`) lets an operation accept *any* completion token instead. Whatever the API shape, the implementation must keep net-snmp out of the headers (ADR 0005).

## Decision

Every Session Operation is an Asio asynchronous operation with completion signature `void(Result<std::vector<Varbind>>)`:

```cpp
template <asio::completion_token_for<VarbindsSignature> Token = asio::deferred_t>
auto get(std::vector<Oid> oids, Token&& token = {});   // likewise getNext, getBulk, set, walk
```

- **Boundary.** The header-side template calls `asio::async_initiate`. Its initiation type-erases the handler into an `asio::any_completion_handler<VarbindsSignature>` and crosses into `session.cpp`. The library is compiled once and net-snmp stays out of the headers.
- **Single request/response Operations** (get, getNext, getBulk, set) are callback primitives. The handler is stored and completed from net-snmp's callback, always via `asio::post`. Wrapping them in a coroutine would add a frame and nothing else.
- **Walk** is a genuine multi-step composition, and is implemented with `asio::co_composed`: a coroutine that issues getBulk until it leaves the subtree.
- **Default token.** The default token is `asio::deferred`, spelled out in each signature so the header documents it. This makes `co_await session.get(oids)` work directly.
- **Naming.** Operations are named after the SNMP operation (`get`, `getNext`, `getBulk`, `set`, `walk`), without Asio's conventional `async_` prefix. Every public operation on a Session is asynchronous, so the prefix would carry no information. Forgetting to `co_await` is still caught: the default `deferred` operation is `[[nodiscard]]`, and GCC and Clang warn when it is dropped.
- **Cancellation.** Per-operation cancellation slots are honoured: terminal, partial and total cancellation all complete that Operation with `TransportError::aborted`. The Walk enables terminal cancellation and forwards it to its in-flight getBulk. net-snmp cannot dequeue a single request. A request that was already sent keeps being retransmitted while other Operations on the Session are in flight. Once none are, the library closes the net-snmp session, which drops it, and reopens the session for the next Operation. Cancelling a sent SET therefore does not mean the agent did not apply it.

## Consequences

- Works with `co_await` (default `deferred`, or `use_awaitable`), plain callbacks, `use_future`, and any other token. All are covered by integration tests.
- Errors travel in `Result`, not as a leading `error_code`, so `as_tuple`/`redirect_error` are unnecessary and awaiting never throws for SNMP failures (ADR 0003).
