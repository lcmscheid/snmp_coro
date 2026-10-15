// SPDX-License-Identifier: MIT
//
// A real net-snmp agent (snmpd) started once per test process on a free loopback port, with one
// USM user per credential shape. Tests SKIP when snmpd is unavailable.
#pragma once

#include <snmp_coro/snmp_coro.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_tostring.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>

#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

template <>
struct Catch::StringMaker<snmp_coro::Error::Code> {
    static std::string convert(const snmp_coro::Error::Code& code) {
        return std::visit([](auto c) { return std::string(snmp_coro::toString(c)); }, code);
    }
};

template <>
struct Catch::StringMaker<snmp_coro::Error> {
    static std::string convert(const snmp_coro::Error& error) {
        return snmp_coro::SnmpError(error).what();
    }
};

namespace test {

using Varbinds = std::vector<snmp_coro::Varbind>;

inline const std::string authPass = "authpass123";
inline const std::string privPass = "privpass123";

// MIB-2 objects every snmpd serves.
inline const snmp_coro::Oid systemGroup{"1.3.6.1.2.1.1"};
inline const snmp_coro::Oid sysDescr{"1.3.6.1.2.1.1.1.0"};
inline const snmp_coro::Oid sysObjectId{"1.3.6.1.2.1.1.2.0"};
inline const snmp_coro::Oid sysUpTime{"1.3.6.1.2.1.1.3.0"};
inline const snmp_coro::Oid sysContact{"1.3.6.1.2.1.1.4.0"};
inline const snmp_coro::Oid sysName{"1.3.6.1.2.1.1.5.0"};
inline const snmp_coro::Oid sysLocation{"1.3.6.1.2.1.1.6.0"};
inline const snmp_coro::Oid snmpInPkts{"1.3.6.1.2.1.11.1.0"};

class Agent {
public:
    /// Starts snmpd on first use; SKIPs the calling test if that is impossible.
    static Agent& instance();

    /// A private agent for tests that stop, restart or replace it. @p engineId (text, 1 to 27
    /// octets) fixes its snmpEngineID; @p port 0 picks a free one. SKIPs if snmpd cannot start.
    static std::unique_ptr<Agent> spawn(const std::string& engineId, unsigned short port = 0);

    /// Stops snmpd (SIGTERM, so it saves engineBoots) and starts it again on the same port and
    /// persistent directory: the engineID stays, engineBoots increases. SKIPs on failure.
    void restart();

    /// Stops snmpd; the port is free afterwards.
    void stop();

    Agent(const Agent&) = delete;
    Agent& operator=(const Agent&) = delete;
    Agent(Agent&&) = delete;
    Agent& operator=(Agent&&) = delete;
    ~Agent();

    [[nodiscard]] const boost::asio::ip::udp::endpoint& endpoint() const noexcept {
        return m_endpoint;
    }

private:
    Agent() = default;
    bool start(std::string& why);

    boost::asio::ip::udp::endpoint m_endpoint;
    std::filesystem::path m_directory;
    std::string m_engineId;
    int m_starts{0};
    int m_pid{-1};
};

/// The users configured in the agent (see agent.cpp).
struct NamedCredentials {
    std::string name;
    snmp_coro::Credentials credentials;
    bool writable;
};
std::vector<NamedCredentials> allUsers();
snmp_coro::Credentials readWriteUser(); // sha256aes

/// Runs @p start with a callback token and drives @p context until it completes.
template <class Start>
snmp_coro::Result<Varbinds> wait(boost::asio::io_context& context, Start&& start) {
    std::optional<snmp_coro::Result<Varbinds>> out;
    std::forward<Start>(start)(
        [&out](snmp_coro::Result<Varbinds> result) { out = std::move(result); });
    context.restart();
    context.run();
    REQUIRE(out.has_value());
    return std::move(*out);
}

/// A loopback endpoint with nothing listening.
boost::asio::ip::udp::endpoint deadEndpoint();

/// Short timeouts so failures are quick.
snmp_coro::Options fastOptions();

/// A session against the shared agent.
snmp_coro::Session makeSession(boost::asio::io_context& context,
                               const snmp_coro::Credentials& credentials,
                               snmp_coro::Options options = fastOptions());

} // namespace test
