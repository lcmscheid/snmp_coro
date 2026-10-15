// SPDX-License-Identifier: MIT
#include <snmp_coro/varbind.hpp>

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>

using namespace snmp_coro;

namespace {

const Oid sysName{"1.3.6.1.2.1.1.5.0"};

void validate(const Varbind& varbind) {
    const std::vector<Varbind> one{varbind};
    detail::validateForSet(one);
}

} // namespace

TEST_CASE("Varbind factories pair type and value", "[varbind]") {
    CHECK(Varbind::integer(sysName, -5).value == Value{std::int64_t{-5}});
    CHECK(Varbind::counter64(sysName, 1ULL << 40U).type == AsnType::counter64);
    CHECK(Varbind::objectId(sysName, Oid("1.3.6")).value == Value{Oid("1.3.6")});
    CHECK(std::holds_alternative<std::monostate>(Varbind::null(sysName).value));
}

TEST_CASE("validateForSet accepts every factory-built settable varbind", "[varbind]") {
    CHECK_NOTHROW(validate(Varbind::integer(sysName, std::numeric_limits<std::int32_t>::min())));
    CHECK_NOTHROW(validate(Varbind::octetString(sysName, "router-1")));
    CHECK_NOTHROW(validate(Varbind::objectId(sysName, Oid("1.3.6.1"))));
    CHECK_NOTHROW(
        validate(Varbind::ipAddress(sysName, boost::asio::ip::make_address_v4("10.0.0.1"))));
    CHECK_NOTHROW(validate(Varbind::counter32(sysName, 1)));
    CHECK_NOTHROW(validate(Varbind::gauge(sysName, std::numeric_limits<std::uint32_t>::max())));
    CHECK_NOTHROW(validate(Varbind::timeticks(sysName, 100)));
    CHECK_NOTHROW(validate(Varbind::counter64(sysName, std::numeric_limits<std::uint64_t>::max())));
    CHECK_NOTHROW(validate(Varbind::opaque(sysName, "\x01\x02")));
}

TEST_CASE("validateForSet rejects programmer errors before anything is sent", "[varbind]") {
    CHECK_THROWS_AS(detail::validateForSet({}), std::invalid_argument);
    CHECK_THROWS_AS(validate(Varbind::null(sysName)), std::invalid_argument);
    CHECK_THROWS_AS(validate(Varbind{sysName, AsnType::integer, std::string("5")}),
                    std::invalid_argument);
    CHECK_THROWS_AS(validate(Varbind{sysName, AsnType::integer, std::int64_t{1} << 31U}),
                    std::invalid_argument);
    CHECK_THROWS_AS(validate(Varbind{sysName, AsnType::gauge, std::uint64_t{1} << 32U}),
                    std::invalid_argument);
    CHECK_THROWS_AS(
        validate(Varbind{sysName, AsnType::octetString, NoSuch{NoSuch::Kind::noSuchObject}}),
        std::invalid_argument);
    CHECK_THROWS_AS(validate(Varbind{sysName, AsnType::oid, std::string("1.3.6")}),
                    std::invalid_argument);
}
