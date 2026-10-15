// SPDX-License-Identifier: MIT
#include <snmp_coro/oid.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <stdexcept>
#include <string>
#include <vector>

using snmp_coro::Oid;

TEST_CASE("Oid parses numeric dotted strings", "[oid]") {
    const Oid oid("1.3.6.1.2.1.1.1.0");
    CHECK(oid.size() == 9);
    CHECK(oid.toString() == "1.3.6.1.2.1.1.1.0");
    CHECK(Oid(".1.3.6.1") == Oid("1.3.6.1"));
    CHECK(Oid("1.3.4294967295").subids().back() == 4294967295U);
    CHECK(Oid("2.999").toString() == "2.999"); // second arc is unbounded under joint-iso-itu-t
}

TEST_CASE("Oid rejects anything that is not a valid numeric OID", "[oid]") {
    const std::string bad = GENERATE(as<std::string>{}, "", ".", "1", "1.", ".1.3.", "1..3",
                                     "1.3.a", "1.3.-1", "1.3.+1", " 1.3", "1.3 ", "1.3.4294967296",
                                     "3.1", "0.40", "1.40", "iso.3.6", "sysDescr.0", "1,3,6");
    CAPTURE(bad);
    CHECK_THROWS_AS(Oid(bad), std::invalid_argument);
}

TEST_CASE("Oid enforces the 128 sub-identifier limit", "[oid]") {
    std::string longest = "1.3";
    for (int i = 2; i < 128; ++i) {
        longest += ".1";
    }
    CHECK(Oid(longest).size() == 128);
    CHECK_THROWS_AS(Oid(longest + ".1"), std::invalid_argument);

    const std::vector<std::uint32_t> tooMany(129, 1);
    CHECK_THROWS_AS(Oid(std::span<const std::uint32_t>(tooMany)), std::invalid_argument);
}

TEST_CASE("Oid constructs from sub-identifiers", "[oid]") {
    CHECK(Oid{1, 3, 6, 1} == Oid("1.3.6.1"));
    CHECK_THROWS_AS((Oid{1}), std::invalid_argument);
    CHECK_THROWS_AS((Oid{3, 1}), std::invalid_argument);
}

TEST_CASE("Oid orders lexicographically, as getNext does", "[oid]") {
    CHECK(Oid("1.3.6") < Oid("1.3.6.1"));
    CHECK(Oid("1.3.6.1") < Oid("1.3.7"));
    CHECK(Oid("1.3.6.2") < Oid("1.3.6.10")); // numeric, not textual
    CHECK(Oid("1.3.6.1") == Oid("1.3.6.1"));
}

TEST_CASE("Oid::isPrefixOf", "[oid]") {
    const Oid system("1.3.6.1.2.1.1");
    CHECK(system.isPrefixOf(Oid("1.3.6.1.2.1.1.5.0")));
    CHECK(system.isPrefixOf(system));
    CHECK_FALSE(system.isPrefixOf(Oid("1.3.6.1.2.1.2")));
    CHECK_FALSE(system.isPrefixOf(Oid("1.3.6.1.2.1")));
    CHECK_FALSE(Oid("1.3.6.1.2.1.1").isPrefixOf(Oid("1.3.6.1.2.1.10")));
}
