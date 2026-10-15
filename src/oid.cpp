// SPDX-License-Identifier: MIT
#include <snmp_coro/oid.hpp>

#include <algorithm>
#include <charconv>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>

namespace snmp_coro {
namespace {

void validate(std::span<const std::uint32_t> subids) {
    if (subids.size() < Oid::minLength || subids.size() > Oid::maxLength) {
        throw std::invalid_argument("OID must have between 2 and 128 sub-identifiers, got " +
                                    std::to_string(subids.size()));
    }
    if (subids[0] > 2) {
        throw std::invalid_argument("OID first arc must be 0, 1 or 2, got " +
                                    std::to_string(subids[0]));
    }
    if (subids[0] < 2 && subids[1] >= 40) {
        throw std::invalid_argument("OID second arc must be below 40 when the first is 0 or 1");
    }
}

std::vector<std::uint32_t> parse(std::string_view dotted) {
    const std::string_view original = dotted;
    if (dotted.starts_with('.')) {
        dotted.remove_prefix(1);
    }
    std::vector<std::uint32_t> subids;
    while (true) {
        const auto dot = dotted.find('.');
        const std::string_view arc = dotted.substr(0, dot);
        std::uint32_t value{};
        const auto* const first = arc.data();
        const auto* const last = std::to_address(arc.end());
        const auto [ptr, ec] = std::from_chars(first, last, value);
        if (arc.empty() || ec != std::errc{} || ptr != last) {
            throw std::invalid_argument("not a numeric OID: \"" + std::string(original) + '"');
        }
        if (subids.size() == Oid::maxLength) {
            throw std::invalid_argument("OID has more than 128 sub-identifiers");
        }
        subids.push_back(value);
        if (dot == std::string_view::npos) {
            break;
        }
        dotted.remove_prefix(dot + 1);
    }
    return subids;
}

} // namespace

Oid::Oid(std::string_view dotted) : m_subids(parse(dotted)) {
    validate(m_subids);
}

Oid::Oid(std::span<const std::uint32_t> subids) : m_subids(subids.begin(), subids.end()) {
    validate(m_subids);
}

Oid::Oid(std::initializer_list<std::uint32_t> subids) : m_subids(subids) {
    validate(m_subids);
}

bool Oid::isPrefixOf(const Oid& other) const noexcept {
    return m_subids.size() <= other.m_subids.size() &&
           std::equal(m_subids.begin(), m_subids.end(), other.m_subids.begin());
}

std::string Oid::toString() const {
    std::string out;
    out.reserve(m_subids.size() * 4);
    for (const auto subid : m_subids) {
        if (!out.empty()) {
            out += '.';
        }
        out += std::to_string(subid);
    }
    return out;
}

} // namespace snmp_coro
