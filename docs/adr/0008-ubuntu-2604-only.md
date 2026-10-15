# Support Ubuntu 26.04 LTS only

Status: Accepted

The only supported platform is **Ubuntu 26.04 LTS**, and CI runs only on GitHub's `ubuntu-26.04` runner. The minimum versions are the ones that platform ships:

| | Version |
|---|---|
| GCC | 15.2 |
| Clang, clang-tidy, clang-format | 22 |
| CMake | 4.2 |
| Boost | 1.90 |
| net-snmp | 5.9.4 |
| OpenSSL | 3.5 |
| Catch2 | 3.7 |

The project does not support older toolchains, so it carries no workarounds for them:

- No guard against GCC 13's internal compiler error on a braced list inside `co_await`. `co_await session.get({oid})` is the normal form, and the tests use it.
- No GCC 13 `-Wmismatched-new-delete` suppression around `co_composed`. GCC 15 does not report it.
- `asio::co_composed` (Boost ≥ 1.86) is used instead of `asio::experimental::co_composed`.
- No pip-installed CMake: the distribution's CMake 4 is enough.
- No OpenSSL legacy-provider config for DES: OpenSSL 3.5 on 26.04 does not need it. ADR 0004 is superseded.

Every claim above was verified on an Ubuntu 26.04.1 root filesystem before adopting this decision. Under GCC 15 the debug, ASan+UBSan and shared presets build with zero warnings, as does Clang 22 with clang-tidy 22, and all tests pass against 26.04's `snmpd`.

Consequence: users on Ubuntu 24.04, which ships Boost 1.83 and GCC 13, cannot build from distribution packages. That is accepted.

The project stays on C++20. `std::expected`, which would replace `Result` under ADR 0003, needs C++23; that would be a separate decision.
