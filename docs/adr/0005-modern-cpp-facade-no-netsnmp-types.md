# Modern C++ facade: no net-snmp types in the public API

Status: Accepted

Every net-snmp data structure is translated at the library boundary. Consumers see only standard and Boost types with scoped, fixed-width enums:

- ASN types and v2 exception kinds are `enum class : std::uint8_t`.
- PDU error-status and USM/transport failure codes are `enum class`es, never raw `SNMP_ERR_*`/`SNMPERR_*` ints.
- Timeouts are `std::chrono` durations, never `timeval`.
- OIDs are a validated `snmp_coro::Oid` value type, never `::oid` arrays or `MAX_OID_LEN`.
- Varbind values are typed: `std::int64_t`, `std::uint64_t`, `std::string` (bytes), `Oid`, `boost::asio::ip::address_v4`, `NoSuch`, or `std::monostate` for null.
- The target is a `boost::asio::ip::udp::endpoint`. The public API never takes an address string; the seam formats net-snmp's `peername` from the endpoint internally.

Consequences:

1. Invalid inputs (a malformed dotted OID, an unspecified address, a missing key for the declared security level, a passphrase under 8 octets) **fail before the net-snmp stack is touched**, when the `Oid`, `Credentials` or `Session` is constructed. `Credentials` has named constructors, so a missing key cannot even be expressed.
2. All net-snmp headers are quarantined to `src/session.cpp`. Consumers never include `net-snmp/*`, and net-snmp is a `PRIVATE` link dependency. Verified on an installed package: the consumer's compile line never mentions net-snmp, and the shared library exports only `snmp_coro::` symbols (hidden visibility by default).

The rule for anything added later: translation happens at one seam in `session.cpp`, never sprinkled through the headers.
