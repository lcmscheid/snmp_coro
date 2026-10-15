// SPDX-License-Identifier: MIT
//
// get / getNext / getBulk / set / walk against a real snmpd, across the credential matrix and
// across completion tokens (ADR 0007).
#include "agent.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/generators/catch_generators_range.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/use_future.hpp>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>

using namespace snmp_coro;
using namespace test;

TEST_CASE("get works for every security level and protocol", "[get]") {
    const auto user = GENERATE(from_range(allUsers()));
    CAPTURE(user.name);
    boost::asio::io_context context;
    auto session = makeSession(context, user.credentials);

    const auto result = wait(
        context, [&](auto handler) { session.get({sysDescr, sysObjectId, sysUpTime}, handler); });
    REQUIRE(result.has_value());
    REQUIRE(result->size() == 3);
    CHECK((*result)[0].oid == sysDescr);
    CHECK((*result)[0].type == AsnType::octetString);
    CHECK_FALSE(std::get<std::string>((*result)[0].value).empty());
    CHECK((*result)[1].type == AsnType::oid);
    CHECK((*result)[2].type == AsnType::timeticks);
}

TEST_CASE("getNext returns the lexicographic successor", "[getNext]") {
    boost::asio::io_context context;
    auto session = makeSession(context, readWriteUser());
    const auto result =
        wait(context, [&](auto handler) { session.getNext({systemGroup}, handler); });
    REQUIRE(result.has_value());
    REQUIRE(result->size() == 1);
    CHECK(result->front().oid == sysDescr);
}

TEST_CASE("getBulk returns up to maxRepetitions successors", "[getBulk]") {
    boost::asio::io_context context;
    auto options = fastOptions();
    options.maxRepetitions = 4;
    auto session = makeSession(context, readWriteUser(), options);
    const auto result =
        wait(context, [&](auto handler) { session.getBulk({systemGroup}, handler); });
    REQUIRE(result.has_value());
    REQUIRE(result->size() == 4);
    CHECK(result->front().oid == sysDescr);
    CHECK(std::ranges::is_sorted(*result, {}, &Varbind::oid));
}

TEST_CASE("walk collects the whole subtree across several getBulk pages", "[walk]") {
    boost::asio::io_context context;
    auto options = fastOptions();
    options.maxRepetitions = 3; // force many pages
    auto session = makeSession(context, readWriteUser(), options);
    const auto result = wait(context, [&](auto handler) { session.walk(systemGroup, handler); });
    REQUIRE(result.has_value());
    CHECK(result->size() > std::size_t{9}); // more than three pages of three
    CHECK(std::ranges::all_of(*result, [](const Varbind& vb) {
        return systemGroup.isPrefixOf(vb.oid) && vb.oid != systemGroup;
    }));
    CHECK(std::ranges::adjacent_find(*result, [](const Varbind& a, const Varbind& b) {
              return !(a.oid < b.oid);
          }) == result->end());
    CHECK(std::ranges::any_of(*result, [](const Varbind& vb) { return vb.oid == sysName; }));
}

TEST_CASE("walk stops at Options::maxWalkVarbinds", "[walk]") {
    boost::asio::io_context context;
    const auto walkWith = [&](std::size_t limit) {
        auto options = fastOptions();
        options.maxRepetitions = 3;
        options.maxWalkVarbinds = limit;
        auto session = makeSession(context, readWriteUser(), options);
        return wait(context, [&](auto handler) { session.walk(systemGroup, handler); });
    };
    const auto full = walkWith(std::numeric_limits<std::size_t>::max());
    REQUIRE(full.has_value());
    const std::size_t count = full->size();
    REQUIRE(count > 1);

    const auto exact = walkWith(count);
    REQUIRE(exact.has_value());
    CHECK(exact->size() == count);

    const auto over = walkWith(count - 1);
    REQUIRE_FALSE(over.has_value());
    CHECK(over.error().code == Error::Code{TransportError::limitExceeded});
    CHECK(over.error().flavour() == ErrorFlavour::transport);
}

TEST_CASE("walk below a leaf is empty", "[walk]") {
    boost::asio::io_context context;
    auto session = makeSession(context, readWriteUser());
    const auto result = wait(context, [&](auto handler) { session.walk(sysDescr, handler); });
    REQUIRE(result.has_value());
    CHECK(result->empty());
}

TEST_CASE("set writes values that a later get reads back", "[set]") {
    boost::asio::io_context context;
    auto session = makeSession(context, readWriteUser());
    const std::string contact = "noc@example.net";
    const std::string location = "rack 7";

    const auto set = wait(context, [&](auto handler) {
        session.set({Varbind::octetString(sysContact, contact),
                     Varbind::octetString(sysLocation, location)},
                    handler);
    });
    REQUIRE(set.has_value());
    CHECK(set->size() == 2);

    const auto get =
        wait(context, [&](auto handler) { session.get({sysContact, sysLocation}, handler); });
    REQUIRE(get.has_value());
    CHECK(std::get<std::string>((*get)[0].value) == contact);
    CHECK(std::get<std::string>((*get)[1].value) == location);
}

TEST_CASE("Missing objects come back as NoSuch values, not errors", "[get]") {
    boost::asio::io_context context;
    auto session = makeSession(context, readWriteUser());
    const auto result = wait(context, [&](auto handler) {
        session.get({Oid("1.3.6.1.2.1.1.5.1"), Oid("1.3.6.1.4.1.99999.1.0")}, handler);
    });
    REQUIRE(result.has_value());
    for (const auto& vb : *result) {
        CHECK(vb.type == AsnType::null);
        REQUIRE(std::holds_alternative<NoSuch>(vb.value));
    }
    CHECK(std::get<NoSuch>((*result)[0].value).value == NoSuch::Kind::noSuchInstance);
}

TEST_CASE("Application types are decoded", "[types]") {
    boost::asio::io_context context;
    auto session = makeSession(context, readWriteUser());
    const auto result = wait(context, [&](auto handler) {
        session.get({snmpInPkts, Oid("1.3.6.1.2.1.4.20.1.1.127.0.0.1")}, handler);
    });
    REQUIRE(result.has_value());
    CHECK((*result)[0].type == AsnType::counter32);
    CHECK(std::get<std::uint64_t>((*result)[0].value) > 0);
    CHECK((*result)[1].type == AsnType::ipAddress);
    CHECK(std::get<boost::asio::ip::address_v4>((*result)[1].value).to_string() == "127.0.0.1");
}

TEST_CASE("Many operations are multiplexed over one Session", "[multiplex]") {
    boost::asio::io_context context;
    auto session = makeSession(context, readWriteUser());
    constexpr int count = 100;
    int succeeded = 0;
    for (int i = 0; i < count; ++i) {
        session.get({sysUpTime}, [&succeeded](const Result<Varbinds>& result) {
            succeeded += result.has_value() ? 1 : 0;
        });
    }
    context.run();
    CHECK(succeeded == count);
}

namespace {

// Named coroutines rather than capturing lambdas (C++ Core Guidelines CP.51).
boost::asio::awaitable<void> getAndWalk(Session& session, std::optional<Result<Varbinds>>& got,
                                        std::optional<Result<Varbinds>>& walked) {
    got = co_await session.get({sysName});
    walked = co_await session.walk(systemGroup);
}

boost::asio::awaitable<void> getNextWithUseAwaitable(Session& session,
                                                     std::optional<Result<Varbinds>>& out) {
    out = co_await session.getNext({systemGroup}, boost::asio::use_awaitable);
}

} // namespace

TEST_CASE("Operations accept any completion token", "[tokens]") {
    boost::asio::io_context context;
    auto session = makeSession(context, readWriteUser());

    SECTION("C++20 coroutine with the default deferred token") {
        std::optional<Result<Varbinds>> got;
        std::optional<Result<Varbinds>> walked;
        boost::asio::co_spawn(context, getAndWalk(session, got, walked), boost::asio::detached);
        context.run();
        REQUIRE(got.has_value());
        CHECK(got->has_value());
        REQUIRE(walked.has_value());
        CHECK(walked->has_value());
    }

    SECTION("use_awaitable") {
        std::optional<Result<Varbinds>> out;
        boost::asio::co_spawn(context, getNextWithUseAwaitable(session, out),
                              boost::asio::detached);
        context.run();
        REQUIRE(out.has_value());
        CHECK(out->has_value());
    }

    SECTION("use_future") {
        auto future = session.get({sysName}, boost::asio::use_future);
        context.run();
        CHECK(future.get().has_value());
    }
}
