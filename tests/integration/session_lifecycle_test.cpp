// SPDX-License-Identifier: MIT
//
// Lifetime, cancellation and recovery behaviour of a Session.
#include "agent.hpp"

#include <catch2/catch_test_macros.hpp>

#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/post.hpp>

#include <chrono>
#include <optional>

using namespace snmp_coro;
using namespace test;

TEST_CASE("Destroying a Session aborts its in-flight operations", "[lifecycle]") {
    static_cast<void>(Agent::instance());
    boost::asio::io_context context;
    std::optional<Result<Varbinds>> out;
    {
        // A dead target keeps the operation in flight until we destroy the Session.
        Session session(context, deadEndpoint(), Credentials::noAuthNoPriv("noauthuser"),
                        Options{.timeout = std::chrono::seconds(10), .retries = 0});
        session.get({sysDescr}, [&out](Result<Varbinds> r) { out = std::move(r); });
        context.poll(); // start discovery
        REQUIRE_FALSE(out.has_value());
    }
    context.run();
    REQUIRE(out.has_value());
    REQUIRE_FALSE(out->has_value());
    CHECK(out->error().code == Error::Code{TransportError::aborted});
}

TEST_CASE("Per-operation cancellation aborts only that operation", "[lifecycle][cancel]") {
    boost::asio::io_context context;
    auto session = makeSession(context, readWriteUser());
    REQUIRE(wait(context, [&](auto h) { session.get({sysDescr}, h); }).has_value());

    boost::asio::cancellation_signal signal;
    std::optional<Result<Varbinds>> cancelled;
    std::optional<Result<Varbinds>> other;
    session.walk(Oid("1.3.6.1.2.1"),
                 boost::asio::bind_cancellation_slot(
                     signal.slot(), [&](Result<Varbinds> r) { cancelled = std::move(r); }));
    session.get({sysName}, [&](Result<Varbinds> r) { other = std::move(r); });
    boost::asio::post(context, [&] { signal.emit(boost::asio::cancellation_type::terminal); });
    context.restart();
    context.run();

    REQUIRE(cancelled.has_value());
    REQUIRE_FALSE(cancelled->has_value());
    CHECK(cancelled->error().code == Error::Code{TransportError::aborted});
    REQUIRE(other.has_value());
    CHECK(other->has_value());

    // The Session stays usable.
    CHECK(wait(context, [&](auto h) { session.get({sysDescr}, h); }).has_value());
}

TEST_CASE("A failed discovery is retried by the next operation", "[lifecycle][discovery]") {
    static_cast<void>(Agent::instance());
    boost::asio::io_context context;
    Session session(context, deadEndpoint(), Credentials::noAuthNoPriv("noauthuser"),
                    Options{.timeout = std::chrono::milliseconds(50), .retries = 0});
    for (int attempt = 0; attempt < 2; ++attempt) {
        const auto result = wait(context, [&](auto h) { session.get({sysDescr}, h); });
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().code == Error::Code{TransportError::timeout});
    }
}

TEST_CASE("Discovery against a dead agent never blocks the io_context thread",
          "[lifecycle][discovery]") {
    // Regression: snmp_sess_open clears SNMP_FLAGS_DONT_PROBE, after which net-snmp's "async"
    // send runs a synchronous engineID probe (ADR 0006).
    static_cast<void>(Agent::instance());
    boost::asio::io_context context;
    Session session(context, deadEndpoint(), Credentials::noAuthNoPriv("noauthuser"),
                    Options{.timeout = std::chrono::milliseconds(500), .retries = 1});
    std::optional<Result<Varbinds>> out;
    session.get({sysDescr}, [&](Result<Varbinds> r) { out = std::move(r); });

    const auto started = std::chrono::steady_clock::now();
    context.poll(); // runs submit -> discovery start; must return immediately
    CHECK(std::chrono::steady_clock::now() - started < std::chrono::milliseconds(100));
    CHECK_FALSE(out.has_value());

    context.run();
    REQUIRE(out.has_value());
    CHECK(out->error().code == Error::Code{TransportError::timeout});
}

TEST_CASE("Operations queued during discovery are all sent", "[lifecycle][discovery]") {
    boost::asio::io_context context;
    auto session = makeSession(context, readWriteUser());
    int succeeded = 0;
    for (int i = 0; i < 5; ++i) { // all submitted before the engineID is known
        session.get({sysUpTime},
                    [&](const Result<Varbinds>& r) { succeeded += r.has_value() ? 1 : 0; });
    }
    context.run();
    CHECK(succeeded == 5);
}

TEST_CASE("A Session does not depend on the caller's Credentials after construction",
          "[lifecycle][security]") {
    boost::asio::io_context context;
    std::optional<Session> session;
    {
        // The passphrases live only in this scope: the Session keeps derived keys, not them.
        const auto credentials = readWriteUser();
        session.emplace(makeSession(context, credentials));
    }
    CHECK(wait(context, [&](auto h) { session->get({sysDescr}, h); }).has_value());
}

TEST_CASE("A moved Session keeps working", "[lifecycle]") {
    boost::asio::io_context context;
    auto first = makeSession(context, readWriteUser());
    Session second = std::move(first);
    CHECK(wait(context, [&](auto h) { second.get({sysDescr}, h); }).has_value());
}
