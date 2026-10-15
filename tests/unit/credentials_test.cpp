// SPDX-License-Identifier: MIT
#include <snmp_coro/credentials.hpp>

#include <catch2/catch_test_macros.hpp>

#include <stdexcept>
#include <string>

using snmp_coro::AuthProtocol;
using snmp_coro::Credentials;
using snmp_coro::PrivProtocol;
using snmp_coro::SecurityLevel;

TEST_CASE("Credentials carry exactly the keys their level needs", "[credentials]") {
    const auto none = Credentials::noAuthNoPriv("monitor");
    CHECK(none.level() == SecurityLevel::noAuthNoPriv);
    CHECK_FALSE(none.auth().has_value());
    CHECK_FALSE(none.priv().has_value());

    const auto auth = Credentials::authNoPriv("monitor", AuthProtocol::sha256, "authpass123");
    CHECK(auth.level() == SecurityLevel::authNoPriv);
    REQUIRE(auth.auth().has_value());
    CHECK(auth.auth()->protocol == AuthProtocol::sha256);
    CHECK_FALSE(auth.priv().has_value());

    const auto priv = Credentials::authPriv("monitor", AuthProtocol::md5, "authpass123",
                                            PrivProtocol::des, "privpass123");
    CHECK(priv.level() == SecurityLevel::authPriv);
    REQUIRE(priv.priv().has_value());
    CHECK(priv.priv()->protocol == PrivProtocol::des);
}

TEST_CASE("Credentials reject bad user names", "[credentials]") {
    CHECK_THROWS_AS(Credentials::noAuthNoPriv(""), std::invalid_argument);
    CHECK_THROWS_AS(Credentials::noAuthNoPriv(std::string(33, 'u')), std::invalid_argument);
    CHECK_NOTHROW(Credentials::noAuthNoPriv(std::string(32, 'u')));
}

TEST_CASE("Credentials reject passphrases shorter than 8 octets (RFC 3414)", "[credentials]") {
    CHECK_THROWS_AS(Credentials::authNoPriv("u", AuthProtocol::sha1, "1234567"),
                    std::invalid_argument);
    CHECK_NOTHROW(Credentials::authNoPriv("u", AuthProtocol::sha1, "12345678"));
    CHECK_THROWS_AS(
        Credentials::authPriv("u", AuthProtocol::sha1, "12345678", PrivProtocol::aes128, "short"),
        std::invalid_argument);
}
