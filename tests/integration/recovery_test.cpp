// SPDX-License-Identifier: MIT
//
// Recovery from agent restarts and engineID changes, and what cancellation leaves on the wire.
#include "agent.hpp"

#include <catch2/catch_test_macros.hpp>

#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/ip/address.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>

using namespace snmp_coro;
using namespace test;
using boost::asio::ip::udp;
using namespace std::chrono_literals;

namespace {

/// Forwards datagrams between one client and an agent. While black-holing it drops (and counts)
/// the client's datagrams instead, so a test can see every (re)transmission.
class Relay {
public:
    Relay(boost::asio::io_context& context, udp::endpoint agent)
        : m_front(context, udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0)),
          m_back(context, udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0)),
          m_agent(std::move(agent)) {
        receiveFromClient();
        receiveFromAgent();
    }

    [[nodiscard]] udp::endpoint endpoint() const { return m_front.local_endpoint(); }
    void blackhole(bool on) { m_blackhole = on; }
    [[nodiscard]] std::size_t dropped() const { return m_dropped; }

private:
    void receiveFromClient() {
        m_front.async_receive_from(
            boost::asio::buffer(m_fromClient), m_client,
            [this](const boost::system::error_code& ec, std::size_t size) {
                if (ec) {
                    return;
                }
                if (m_blackhole) {
                    ++m_dropped;
                } else {
                    m_back.send_to(boost::asio::buffer(m_fromClient.data(), size), m_agent);
                }
                receiveFromClient();
            });
    }

    void receiveFromAgent() {
        m_back.async_receive_from(boost::asio::buffer(m_fromAgent), m_sender,
                                  [this](const boost::system::error_code& ec, std::size_t size) {
                                      if (ec) {
                                          return;
                                      }
                                      m_front.send_to(boost::asio::buffer(m_fromAgent.data(), size),
                                                      m_client);
                                      receiveFromAgent();
                                  });
    }

    udp::socket m_front;
    udp::socket m_back;
    udp::endpoint m_agent;
    udp::endpoint m_client;
    udp::endpoint m_sender;
    std::array<char, 65536> m_fromClient{};
    std::array<char, 65536> m_fromAgent{};
    bool m_blackhole{false};
    std::size_t m_dropped{0};
};

/// Like test::wait, for an io_context that never runs out of work (the Relay keeps it busy).
template <class Start>
Result<Varbinds> await(boost::asio::io_context& context, Start&& start) {
    std::optional<Result<Varbinds>> out;
    std::forward<Start>(start)([&out](Result<Varbinds> result) { out = std::move(result); });
    context.restart();
    const auto deadline = std::chrono::steady_clock::now() + 10s;
    while (!out && std::chrono::steady_clock::now() < deadline) {
        context.run_one_for(100ms);
    }
    REQUIRE(out.has_value());
    return std::move(*out);
}

void runFor(boost::asio::io_context& context, std::chrono::milliseconds duration) {
    context.restart();
    context.run_for(duration);
}

} // namespace

TEST_CASE("An agent restart (engineBoots change) is recovered within the operation", "[recovery]") {
    // The agent's engineBoots increases, so the Session's cached time is stale. Against snmpd
    // 5.9.4 net-snmp recovers by retransmitting; the operation must still succeed.
    const Oid snmpEngineBoots{"1.3.6.1.6.3.10.2.1.2.0"};
    auto agent = Agent::spawn("snmpcoroBoots");
    boost::asio::io_context context;
    Session session(context, agent->endpoint(), readWriteUser(), fastOptions());
    const auto before = wait(context, [&](auto h) { session.get({snmpEngineBoots}, h); });
    REQUIRE(before.has_value());

    agent->restart();

    const auto after = wait(context, [&](auto h) { session.get({snmpEngineBoots}, h); });
    INFO((after.has_value() ? std::string("ok") : SnmpError(after.error()).what()));
    REQUIRE(after.has_value());
    // Only a higher engineBoots makes the agent answer notInTimeWindow.
    CHECK(std::get<std::int64_t>(after->front().value) >
          std::get<std::int64_t>(before->front().value));
}

TEST_CASE("A changed agent engineID is rediscovered by the next operation", "[recovery]") {
    // Regression: the engineID was discovered once, so every later operation timed out forever.
    auto first = Agent::spawn("snmpcoroFirst");
    const auto target = first->endpoint();
    boost::asio::io_context context;
    Session session(context, target, readWriteUser(), fastOptions());
    REQUIRE(wait(context, [&](auto h) { session.get({sysDescr}, h); }).has_value());

    first->stop();
    const auto second = Agent::spawn("snmpcoroSecond", target.port());

    // The operation in flight when the change happens fails: net-snmp drops the agent's
    // unknownEngineID Report (it has no USM user for the new engine), so it times out...
    const auto noticed = wait(context, [&](auto h) { session.get({sysDescr}, h); });
    REQUIRE_FALSE(noticed.has_value());
    CHECK(noticed.error().code == Error::Code{TransportError::timeout});

    // ...and the Session rediscovers the engine instead of failing forever.
    for (int i = 0; i < 2; ++i) {
        const auto result = wait(context, [&](auto h) { session.get({sysDescr}, h); });
        INFO((result.has_value() ? std::string("ok") : SnmpError(result.error()).what()));
        CHECK(result.has_value());
    }
}

TEST_CASE("A cancelled request is not retransmitted after cancellation", "[recovery][cancel]") {
    // Regression: cancellation only forgot the operation; net-snmp kept the request queued and
    // retransmitted it as soon as later operations re-armed its timer.
    boost::asio::io_context context;
    Relay relay(context, Agent::instance().endpoint());
    Session session(context, relay.endpoint(), readWriteUser(),
                    Options{.timeout = 100ms, .retries = 5});
    REQUIRE(await(context, [&](auto h) { session.get({sysDescr}, h); }).has_value());

    relay.blackhole(true);
    boost::asio::cancellation_signal signal;
    std::optional<Result<Varbinds>> cancelled;
    session.set({Varbind::octetString(sysContact, "never applied")},
                boost::asio::bind_cancellation_slot(
                    signal.slot(), [&](Result<Varbinds> r) { cancelled = std::move(r); }));
    runFor(context, 50ms); // sent once, no retransmission yet
    REQUIRE(relay.dropped() == 1);
    signal.emit(boost::asio::cancellation_type::terminal);
    runFor(context, 50ms);
    REQUIRE(cancelled.has_value());
    CHECK(cancelled->error().code == Error::Code{TransportError::aborted});

    // A later operation must not revive the cancelled request's retransmissions.
    const auto later = await(context, [&](auto h) { session.get({sysDescr}, h); });
    REQUIRE_FALSE(later.has_value());
    CHECK(later.error().code == Error::Code{TransportError::timeout});
    CHECK(relay.dropped() == 1 + 6); // the get's own 1 + 5 retries only

    relay.blackhole(false);
    CHECK(await(context, [&](auto h) { session.get({sysDescr}, h); }).has_value());
}

TEST_CASE("A Session torn down with its io_context never completes in-flight operations",
          "[recovery][lifecycle]") {
    // ~SessionImpl must drop pending handlers before closing net-snmp sessions: snmp_sess_close
    // runs OP_TIMED_OUT callbacks, which would post completions to the dying io_context. (Asio
    // tolerates that today, so this covers the path rather than reproducing a crash.)
    std::optional<Result<Varbinds>> out;
    {
        boost::asio::io_context context;
        Relay relay(context, Agent::instance().endpoint());
        auto session = std::make_unique<Session>(context, relay.endpoint(), readWriteUser(),
                                                 Options{.timeout = 10s, .retries = 0});
        REQUIRE(await(context, [&](auto h) { session->get({sysDescr}, h); }).has_value());
        relay.blackhole(true);
        session->get({sysDescr}, [&out](Result<Varbinds> r) { out = std::move(r); });
        runFor(context, 50ms); // queued in net-snmp
        session.reset();       // outside run(), context not stopped: the shutdown is posted
    } // the io_context is destroyed without running it
    CHECK_FALSE(out.has_value());
}
