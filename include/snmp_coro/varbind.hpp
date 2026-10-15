// SPDX-License-Identifier: MIT
#pragma once

#include <snmp_coro/export.hpp>
#include <snmp_coro/oid.hpp>

#include <boost/asio/ip/address_v4.hpp>

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <variant>

namespace snmp_coro {

/// SMIv2 application types, plus `null` (request varbinds and v2 exception values).
enum class AsnType : std::uint8_t {
    null,
    integer,     ///< Integer32; value holds std::int64_t.
    octetString, ///< value holds std::string (raw bytes, not necessarily UTF-8).
    oid,         ///< value holds Oid.
    ipAddress,   ///< value holds boost::asio::ip::address_v4.
    counter32,   ///< value holds std::uint64_t.
    gauge,       ///< Gauge32 / Unsigned32; value holds std::uint64_t.
    timeticks,   ///< value holds std::uint64_t (hundredths of a second).
    counter64,   ///< value holds std::uint64_t.
    opaque,      ///< value holds std::string (raw bytes).
};

/// SNMPv2 exception values (RFC 3416 §3) returned in place of a value.
struct NoSuch {
    enum class Kind : std::uint8_t { noSuchObject, noSuchInstance, endOfMibView };

    Kind value;

    bool operator==(const NoSuch&) const = default;
};

using Value = std::variant<std::monostate, std::int64_t, std::uint64_t, std::string, Oid,
                           boost::asio::ip::address_v4, NoSuch>;

/// One variable binding. In responses, `type` is `AsnType::null` when `value` holds `NoSuch`.
///
/// The factories below build a varbind whose `type` and `value` agree; `Session::set`
/// rejects any varbind where they do not.
struct SNMP_CORO_EXPORT Varbind {
    Oid oid;
    AsnType type{AsnType::null};
    Value value;

    bool operator==(const Varbind&) const = default;

    [[nodiscard]] static Varbind null(Oid oid);
    [[nodiscard]] static Varbind integer(Oid oid, std::int32_t value);
    [[nodiscard]] static Varbind octetString(Oid oid, std::string value);
    [[nodiscard]] static Varbind objectId(Oid oid, Oid value);
    [[nodiscard]] static Varbind ipAddress(Oid oid, boost::asio::ip::address_v4 value);
    [[nodiscard]] static Varbind counter32(Oid oid, std::uint32_t value);
    [[nodiscard]] static Varbind gauge(Oid oid, std::uint32_t value);
    [[nodiscard]] static Varbind timeticks(Oid oid, std::uint32_t value);
    [[nodiscard]] static Varbind counter64(Oid oid, std::uint64_t value);
    [[nodiscard]] static Varbind opaque(Oid oid, std::string value);
};

[[nodiscard]] SNMP_CORO_EXPORT std::string_view toString(AsnType value) noexcept;
[[nodiscard]] SNMP_CORO_EXPORT std::string_view toString(NoSuch::Kind value) noexcept;

namespace detail {

/// Rejects programmer errors in a set request before anything is sent (ADR 0003, ADR 0005):
/// an empty list, a type/value mismatch, a value out of range for its type, or a null/NoSuch value.
/// @throws std::invalid_argument
SNMP_CORO_EXPORT void validateForSet(std::span<const Varbind> varbinds);

} // namespace detail
} // namespace snmp_coro
