// SPDX-License-Identifier: MIT
#pragma once

#include <snmp_coro/export.hpp>

#include <compare>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace snmp_coro {

/// A validated, numeric SNMP object identifier.
///
/// Invariant (checked on every construction, so an `Oid` that exists is always encodable):
/// 2..128 sub-identifiers, the first in [0, 2], the second below 40 when the first is 0 or 1
/// (X.690 §8.19.4), every sub-identifier fits in 32 bits (RFC 2578 §3.5).
///
/// Ordering is the SNMP lexicographic order used by getNext/getBulk.
class SNMP_CORO_EXPORT Oid {
public:
    static constexpr std::size_t minLength = 2;
    static constexpr std::size_t maxLength = 128;

    /// Parses a numeric dotted OID such as "1.3.6.1.2.1.1.1.0". One leading dot is accepted.
    /// Symbolic MIB names are out of scope (ADR 0002).
    /// @throws std::invalid_argument on anything that is not a valid numeric OID.
    explicit Oid(std::string_view dotted);

    /// @throws std::invalid_argument if @p subids violates the invariant.
    explicit Oid(std::span<const std::uint32_t> subids);

    /// @throws std::invalid_argument if @p subids violates the invariant.
    Oid(std::initializer_list<std::uint32_t> subids);

    /// True when this OID equals @p other or is an ancestor of it.
    [[nodiscard]] bool isPrefixOf(const Oid& other) const noexcept;

    [[nodiscard]] std::span<const std::uint32_t> subids() const noexcept { return m_subids; }

    [[nodiscard]] std::size_t size() const noexcept { return m_subids.size(); }

    /// Dotted form without a leading dot, e.g. "1.3.6.1".
    [[nodiscard]] std::string toString() const;

    auto operator<=>(const Oid&) const = default;

private:
    std::vector<std::uint32_t> m_subids;
};

} // namespace snmp_coro
