// SPDX-License-Identifier: MIT
#include <snmp_coro/varbind.hpp>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>

namespace snmp_coro {
namespace {

[[noreturn]] void reject(std::size_t position, const Varbind& varbind, std::string_view why) {
    throw std::invalid_argument("set varbind " + std::to_string(position + 1) + " (" +
                                varbind.oid.toString() + ", " +
                                std::string(toString(varbind.type)) + "): " + std::string(why));
}

template <class T>
const T* valueAs(const Varbind& varbind) noexcept {
    return std::get_if<T>(&varbind.value);
}

} // namespace

Varbind Varbind::null(Oid oid) {
    return {.oid = std::move(oid), .type = AsnType::null, .value = std::monostate{}};
}

Varbind Varbind::integer(Oid oid, std::int32_t value) {
    return {.oid = std::move(oid), .type = AsnType::integer, .value = std::int64_t{value}};
}

Varbind Varbind::octetString(Oid oid, std::string value) {
    return {.oid = std::move(oid), .type = AsnType::octetString, .value = std::move(value)};
}

Varbind Varbind::objectId(Oid oid, Oid value) {
    return {.oid = std::move(oid), .type = AsnType::oid, .value = std::move(value)};
}

Varbind Varbind::ipAddress(Oid oid, boost::asio::ip::address_v4 value) {
    return {.oid = std::move(oid), .type = AsnType::ipAddress, .value = value};
}

Varbind Varbind::counter32(Oid oid, std::uint32_t value) {
    return {.oid = std::move(oid), .type = AsnType::counter32, .value = std::uint64_t{value}};
}

Varbind Varbind::gauge(Oid oid, std::uint32_t value) {
    return {.oid = std::move(oid), .type = AsnType::gauge, .value = std::uint64_t{value}};
}

Varbind Varbind::timeticks(Oid oid, std::uint32_t value) {
    return {.oid = std::move(oid), .type = AsnType::timeticks, .value = std::uint64_t{value}};
}

Varbind Varbind::counter64(Oid oid, std::uint64_t value) {
    return {.oid = std::move(oid), .type = AsnType::counter64, .value = value};
}

Varbind Varbind::opaque(Oid oid, std::string value) {
    return {.oid = std::move(oid), .type = AsnType::opaque, .value = std::move(value)};
}

std::string_view toString(AsnType value) noexcept {
    switch (value) {
    case AsnType::null: return "null";
    case AsnType::integer: return "integer";
    case AsnType::octetString: return "octetString";
    case AsnType::oid: return "oid";
    case AsnType::ipAddress: return "ipAddress";
    case AsnType::counter32: return "counter32";
    case AsnType::gauge: return "gauge";
    case AsnType::timeticks: return "timeticks";
    case AsnType::counter64: return "counter64";
    case AsnType::opaque: return "opaque";
    }
    return "unknown";
}

std::string_view toString(NoSuch::Kind value) noexcept {
    switch (value) {
    case NoSuch::Kind::noSuchObject: return "noSuchObject";
    case NoSuch::Kind::noSuchInstance: return "noSuchInstance";
    case NoSuch::Kind::endOfMibView: return "endOfMibView";
    }
    return "unknown";
}

namespace detail {

void validateForSet(std::span<const Varbind> varbinds) {
    if (varbinds.empty()) {
        throw std::invalid_argument("set needs at least one varbind");
    }
    constexpr auto max32 = std::uint64_t{std::numeric_limits<std::uint32_t>::max()};
    for (std::size_t i = 0; i < varbinds.size(); ++i) {
        const Varbind& vb = varbinds[i];
        switch (vb.type) {
        case AsnType::null: reject(i, vb, "null cannot be set");
        case AsnType::integer: {
            const auto* v = valueAs<std::int64_t>(vb);
            if (v == nullptr) {
                reject(i, vb, "value must hold std::int64_t");
            }
            if (*v < std::numeric_limits<std::int32_t>::min() ||
                *v > std::numeric_limits<std::int32_t>::max()) {
                reject(i, vb, "value out of Integer32 range");
            }
            break;
        }
        case AsnType::octetString:
        case AsnType::opaque:
            if (valueAs<std::string>(vb) == nullptr) {
                reject(i, vb, "value must hold std::string");
            }
            break;
        case AsnType::oid:
            if (valueAs<Oid>(vb) == nullptr) {
                reject(i, vb, "value must hold Oid");
            }
            break;
        case AsnType::ipAddress:
            if (valueAs<boost::asio::ip::address_v4>(vb) == nullptr) {
                reject(i, vb, "value must hold boost::asio::ip::address_v4");
            }
            break;
        case AsnType::counter32:
        case AsnType::gauge:
        case AsnType::timeticks: {
            const auto* v = valueAs<std::uint64_t>(vb);
            if (v == nullptr) {
                reject(i, vb, "value must hold std::uint64_t");
            }
            if (*v > max32) {
                reject(i, vb, "value out of 32-bit unsigned range");
            }
            break;
        }
        case AsnType::counter64:
            if (valueAs<std::uint64_t>(vb) == nullptr) {
                reject(i, vb, "value must hold std::uint64_t");
            }
            break;
        default: reject(i, vb, "unknown AsnType");
        }
    }
}

} // namespace detail
} // namespace snmp_coro
