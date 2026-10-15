// SPDX-License-Identifier: MIT
#include <snmp_coro/error.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <vector>

using namespace snmp_coro;

TEST_CASE("Error::flavour follows the active code", "[error]") {
    CHECK(Error{TransportError::timeout, 0, {}}.flavour() == ErrorFlavour::transport);
    CHECK(Error{PduError::notWritable, 1, {}}.flavour() == ErrorFlavour::pduStatus);
    CHECK(Error{SecurityError::authFailure, 0, {}}.flavour() == ErrorFlavour::security);
}

TEST_CASE("PduError values are the RFC 3416 error-status codes", "[error]") {
    CHECK(static_cast<int>(PduError::noError) == 0);
    CHECK(static_cast<int>(PduError::genErr) == 5);
    CHECK(static_cast<int>(PduError::notWritable) == 17);
    CHECK(static_cast<int>(PduError::inconsistentName) == 18);
}

TEST_CASE("Result::value() throws SnmpError carrying the Error", "[error]") {
    const Result<std::vector<int>> failed =
        Error{.code = SecurityError::unknownUser, .message = "no such user"};
    REQUIRE_FALSE(failed.has_value());
    try {
        static_cast<void>(failed.value());
        FAIL("value() did not throw");
    } catch (const SnmpError& e) {
        CHECK(e.error() == failed.error());
        CHECK_THAT(e.what(), Catch::Matchers::ContainsSubstring("security"));
        CHECK_THAT(e.what(), Catch::Matchers::ContainsSubstring("unknownUser"));
    }

    const Result<std::vector<int>> ok = std::vector<int>{1, 2};
    REQUIRE(ok.has_value());
    CHECK(ok->size() == 2);
}

TEST_CASE("toString names every enumerator", "[error]") {
    for (int i = 0; i <= 18; ++i) {
        CHECK(toString(static_cast<PduError>(i)) != "unknown");
    }
    for (int i = 0; i <= static_cast<int>(SecurityError::unexpectedReport); ++i) {
        CHECK(toString(static_cast<SecurityError>(i)) != "unknown");
    }
}
