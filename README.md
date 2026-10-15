# snmp_coro

An MIT-licensed C++20 library that turns net-snmp's SNMPv3 manager operations into Boost.Asio asynchronous operations: get, getNext, getBulk, set and walk. Every operation accepts any completion token, so it works with `co_await`, callbacks or futures. Consumers never see a net-snmp type.

```cpp
#include <snmp_coro/snmp_coro.hpp>

namespace asio = boost::asio;
using namespace snmp_coro;

asio::awaitable<void> poll(Session& session) {
    Result<std::vector<Varbind>> r = co_await session.get({Oid("1.3.6.1.2.1.1.5.0")}); // sysName.0
    if (!r) {
        // r.error().flavour(): transport / pduStatus / security; r.error().code holds the detail
        co_return;
    }
    for (const Varbind& vb : *r) { /* vb.oid, vb.type, vb.value */ }

    auto subtree = co_await session.walk(Oid("1.3.6.1.2.1.2"));   // ifTable & friends
}

int main() {
    asio::io_context io;
    Session session(io, {asio::ip::make_address("192.0.2.10"), 161},
                    Credentials::authPriv("monitor", AuthProtocol::sha256, "auth-passphrase",
                                          PrivProtocol::aes128, "priv-passphrase"));
    asio::co_spawn(io, poll(session), asio::detached);
    io.run();
}
```

See [`examples/walk.cpp`](examples/walk.cpp) for a complete program.

## Design

| Topic | Decision |
|---|---|
| Async model | net-snmp's single-session async API driven by an Asio descriptor and timer. No threads, no blocking calls ([ADR 0001](docs/adr/0001-compose-net-snmp-async-api-with-asio.md)) |
| Scope | SNMPv3 manager only; numeric OIDs; no MIB loading ([ADR 0002](docs/adr/0002-snmpv3-only-scope.md)) |
| Errors | `Result<T>` = `boost::system::result<T, Error>`, with three flavours; exceptions only for programmer errors ([ADR 0003](docs/adr/0003-error-model-expected.md)) |
| API surface | No net-snmp types or headers in the public API ([ADR 0005](docs/adr/0005-modern-cpp-facade-no-netsnmp-types.md)) |
| Discovery & USM | Asynchronous engine discovery; the library owns net-snmp's process-wide USM user table ([ADR 0006](docs/adr/0006-async-engine-discovery-and-usm-ownership.md)) |
| Completion tokens | `async_initiate` + `any_completion_handler` at the boundary; walk built with `co_composed` ([ADR 0007](docs/adr/0007-token-generic-operations.md)) |
| Platform | Ubuntu 26.04 LTS only; no workarounds for older toolchains ([ADR 0008](docs/adr/0008-ubuntu-2604-only.md)) |

Domain vocabulary: [GLOSSARY.md](GLOSSARY.md).

### Things to know

- **One thread.** Run each `io_context` that drives Sessions on a single thread. net-snmp is not thread-safe, so all Sessions in a process must be driven from the same thread. Operations may be *started* from any thread.
- **Process-wide net-snmp state.** The library configures net-snmp for the whole process: no config files, no persistent state in `/var/lib/snmp`, no MIBs. Mixing in other direct net-snmp use in the same process is unsupported.
- **The constructor does no I/O.** Engine discovery happens on the first operation. Operations queued meanwhile are sent once it completes.
- **Passphrases are not retained.** The Session derives the USM master keys in its constructor and keeps only those. You may wipe or destroy your `Credentials` once the Session exists.
- **Walks are bounded.** A walk fails with `TransportError::limitExceeded` once it would collect more than `Options::maxWalkVarbinds` (default 100,000), so a misbehaving agent cannot exhaust memory. Raise the limit for very large tables.
- **A wrong privacy passphrase** surfaces as `TransportError::timeout`: net-snmp discards the agent's unauthenticated decryption-error report.
- **Cancelling a SET that was already sent** does not undo it: the agent may have applied it. The library stops retransmitting it once no other operation on the Session is in flight ([ADR 0007](docs/adr/0007-token-generic-operations.md)).
- **A replaced agent (new engineID)** fails the operations in flight with `TransportError::timeout`. Discovery then runs again, so later operations work without recreating the Session ([ADR 0006](docs/adr/0006-async-engine-discovery-and-usm-ownership.md)).

## Requirements

The supported platform is **Ubuntu 26.04 LTS**, and nothing older ([ADR 0008](docs/adr/0008-ubuntu-2604-only.md)). The minimums are what it ships:

| | Version |
|---|---|
| Compiler | GCC 15.2 or Clang 22 (C++20) |
| CMake | 4.2 |
| Boost (Asio, System; header-only) | 1.90 |
| net-snmp (with OpenSSL 3.5) | 5.9.4 |
| snmpd (integration tests only) | 5.9.4 |

```sh
sudo apt install g++ cmake ninja-build libboost-dev libsnmp-dev libssl-dev snmpd catch2 \
                 clang-22 clang-format-22 clang-tidy-22
```

## Building and testing

```sh
cmake --preset debug          # also: release, asan (ASan+UBSan), tidy (clang 22 + clang-tidy 22), shared
cmake --build --preset debug
ctest --preset debug          # unit tests + integration tests against a real snmpd
```

The integration tests start their own `snmpd` on a free loopback port, with one USM user per security level and protocol. If `snmpd` is not installed they are skipped. No root access or system agent is needed.

Quality gates (all run in CI):

- **Warnings:** `-Wall -Wextra -Wpedantic -Wshadow -Wconversion …` treated as errors.
- **clang-tidy:** [`.clang-tidy`](.clang-tidy), warnings as errors, over the library, tests and examples.
- **clang-format:** [`.clang-format`](.clang-format); check with `clang-format --dry-run --Werror`.
- **Sanitizers:** ASan + UBSan with leak detection (`asan` preset).
- **Shared build:** hidden visibility; only `snmp_coro::` symbols exported (`shared` preset).

## Using it from CMake

```cmake
find_package(snmp_coro 0.1 CONFIG REQUIRED)
target_link_libraries(app PRIVATE snmp_coro::snmp_coro)
```

Or with `FetchContent` / `add_subdirectory`, where tests and examples are off unless this is the top-level project.

## License

MIT; see [LICENSE](LICENSE). net-snmp is under BSD-style licenses and Boost under the Boost Software License, both compatible with MIT.
