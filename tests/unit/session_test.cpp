// SPDX-License-Identifier: MIT
//
// Session behaviour that needs no agent: argument validation and the no-I/O constructor.
#include <snmp_coro/session.hpp>

#include <catch2/catch_test_macros.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>

#include <chrono>
#include <stdexcept>

using namespace snmp_coro;
using boost::asio::ip::udp;

namespace {

const udp::endpoint loopback{boost::asio::ip::make_address("127.0.0.1"), 161};

} // namespace

TEST_CASE("Session construction performs no I/O", "[session]") {
    boost::asio::io_context context;
    const Session session(context, loopback, Credentials::noAuthNoPriv("monitor"));
    // Nothing was scheduled: run() returns immediately.
    CHECK(context.run() == 0);
}

TEST_CASE("Session rejects invalid targets and options", "[session]") {
    boost::asio::io_context context;
    const auto credentials = Credentials::noAuthNoPriv("monitor");
    CHECK_THROWS_AS(Session(context, udp::endpoint(udp::v4(), 161), credentials),
                    std::invalid_argument);
    CHECK_THROWS_AS(Session(context, udp::endpoint(loopback.address(), 0), credentials),
                    std::invalid_argument);
    CHECK_THROWS_AS(
        Session(context, loopback, credentials, Options{.timeout = std::chrono::milliseconds(0)}),
        std::invalid_argument);
    CHECK_THROWS_AS(Session(context, loopback, credentials, Options{.maxRepetitions = 0}),
                    std::invalid_argument);
    CHECK_THROWS_AS(Session(context, loopback, credentials, Options{.maxWalkVarbinds = 0}),
                    std::invalid_argument);
}

TEST_CASE("Session rejects timeouts net-snmp's microsecond timer cannot hold", "[session]") {
    // Regression: the conversion to microseconds overflowed instead of being rejected.
    boost::asio::io_context context;
    const auto credentials = Credentials::noAuthNoPriv("monitor");
    CHECK_THROWS_AS(Session(context, loopback, credentials,
                            Options{.timeout = std::chrono::milliseconds::max()}),
                    std::invalid_argument);
    CHECK_THROWS_AS(Session(context, loopback, credentials,
                            Options{.timeout = std::chrono::milliseconds(9'300'000'000'000'000)}),
                    std::invalid_argument);
    CHECK_NOTHROW(Session(context, loopback, credentials,
                          Options{.timeout = std::chrono::hours(24 * 365 * 1000)}));
}

TEST_CASE("Session operations reject empty requests at the call site", "[session]") {
    boost::asio::io_context context;
    Session session(context, loopback, Credentials::noAuthNoPriv("monitor"));
    CHECK_THROWS_AS(session.get({}), std::invalid_argument);
    CHECK_THROWS_AS(session.getNext({}), std::invalid_argument);
    CHECK_THROWS_AS(session.getBulk({}), std::invalid_argument);
    CHECK_THROWS_AS(session.set({}), std::invalid_argument);
    CHECK_THROWS_AS(session.set({Varbind::null(Oid("1.3.6.1.2.1.1.5.0"))}), std::invalid_argument);
}

TEST_CASE("A moved-from Session throws std::logic_error", "[session]") {
    boost::asio::io_context context;
    Session first(context, loopback, Credentials::noAuthNoPriv("monitor"));
    const Session second(std::move(first));
    // Deliberate use-after-move: that is exactly what is under test.
    // NOLINTNEXTLINE(bugprone-use-after-move,clang-analyzer-cplusplus.Move)
    CHECK_THROWS_AS(first.get({Oid("1.3.6.1")}), std::logic_error);
}
