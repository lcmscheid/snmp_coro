// SPDX-License-Identifier: MIT
//
// The three error flavours (glossary), observed against a real agent.
#include "agent.hpp"

#include <catch2/catch_test_macros.hpp>

#include <boost/asio/ip/address.hpp>

#include <chrono>

using namespace snmp_coro;
using namespace test;

namespace {

Result<Varbinds> getSysDescr(const Credentials& credentials, Options options = fastOptions()) {
    boost::asio::io_context context;
    auto session = makeSession(context, credentials, options);
    return wait(context, [&](auto handler) { session.get({sysDescr}, handler); });
}

template <class Code>
void requireError(const Result<Varbinds>& result, Code code) {
    REQUIRE_FALSE(result.has_value());
    CAPTURE(result.error().message);
    REQUIRE(std::holds_alternative<Code>(result.error().code));
    CHECK(std::get<Code>(result.error().code) == code);
}

} // namespace

TEST_CASE("Transport error: no agent at the target", "[errors][transport]") {
    static_cast<void>(Agent::instance()); // only so the test is skipped together with the rest
    boost::asio::io_context context;
    Session session(context, deadEndpoint(), Credentials::noAuthNoPriv("noauthuser"),
                    Options{.timeout = std::chrono::milliseconds(100), .retries = 1});
    const auto started = std::chrono::steady_clock::now();
    const auto result = wait(context, [&](auto handler) { session.get({sysDescr}, handler); });
    requireError(result, TransportError::timeout);
    CHECK(result.error().flavour() == ErrorFlavour::transport);
    CHECK(std::chrono::steady_clock::now() - started < std::chrono::seconds(3));
}

TEST_CASE("Security errors are classified from USM reports", "[errors][security]") {
    SECTION("unknown user") {
        requireError(getSysDescr(Credentials::authNoPriv("nobody", AuthProtocol::md5, authPass)),
                     SecurityError::unknownUser);
    }
    SECTION("wrong auth passphrase") {
        requireError(getSysDescr(Credentials::authPriv("shaaes", AuthProtocol::sha1, "WRONGpass123",
                                                       PrivProtocol::aes128, privPass)),
                     SecurityError::authFailure);
    }
    SECTION("wrong auth protocol") {
        requireError(getSysDescr(Credentials::authPriv("shaaes", AuthProtocol::md5, authPass,
                                                       PrivProtocol::aes128, privPass)),
                     SecurityError::authFailure);
    }
    SECTION("security level the user is not configured for") {
        requireError(getSysDescr(Credentials::authPriv("md5only", AuthProtocol::md5, authPass,
                                                       PrivProtocol::des, privPass)),
                     SecurityError::unsupportedLevel);
    }
}

TEST_CASE("A wrong privacy passphrase fails (net-snmp drops the unauthenticated report)",
          "[errors][security]") {
    // ADR 0006: the agent cannot decrypt, answers with an unauthenticated decryptionErrors
    // report, and net-snmp discards it, so the operation times out.
    const auto result = getSysDescr(Credentials::authPriv("shaaes", AuthProtocol::sha1, authPass,
                                                          PrivProtocol::aes128, "WRONGpriv123"));
    REQUIRE_FALSE(result.has_value());
    const auto& code = result.error().code;
    const bool expected = code == Error::Code{TransportError::timeout} ||
                          code == Error::Code{SecurityError::decryptFailed};
    CHECK(expected);
}

TEST_CASE("PDU error-status is reported with its error-index", "[errors][pdu]") {
    boost::asio::io_context context;
    auto session = makeSession(context, readWriteUser());

    SECTION("read-only object") {
        const auto result = wait(context, [&](auto handler) {
            session.set(
                {Varbind::octetString(sysName, "ok"), Varbind::octetString(sysDescr, "nope")},
                handler);
        });
        requireError(result, PduError::notWritable);
        CHECK(result.error().flavour() == ErrorFlavour::pduStatus);
        CHECK(result.error().index == 2);
    }
    SECTION("wrong type") {
        const auto result = wait(
            context, [&](auto handler) { session.set({Varbind::integer(sysName, 7)}, handler); });
        requireError(result, PduError::wrongType);
        CHECK(result.error().index == 1);
    }
}

TEST_CASE("A read-only user cannot set", "[errors][pdu]") {
    boost::asio::io_context context;
    auto session =
        makeSession(context, Credentials::authNoPriv("md5only", AuthProtocol::md5, authPass));
    const auto result = wait(
        context, [&](auto handler) { session.set({Varbind::octetString(sysName, "x")}, handler); });
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().flavour() == ErrorFlavour::pduStatus);
}

TEST_CASE("USM keys are never silently reused across Sessions (ADR 0006)",
          "[errors][security][usm]") {
    const auto good = readWriteUser();
    const auto bad = Credentials::authPriv("sha256aes", AuthProtocol::sha256, "WRONGpass123",
                                           PrivProtocol::aes128, privPass);

    SECTION("a wrong passphrase after a good Session was destroyed is rejected") {
        REQUIRE(getSysDescr(good).has_value());
        requireError(getSysDescr(bad), SecurityError::authFailure);
        REQUIRE(getSysDescr(good).has_value());
    }

    SECTION("conflicting keys while a good Session is alive are refused") {
        boost::asio::io_context context;
        auto goodSession = makeSession(context, good);
        REQUIRE(wait(context, [&](auto h) { goodSession.get({sysDescr}, h); }).has_value());

        auto badSession = makeSession(context, bad);
        requireError(wait(context, [&](auto h) { badSession.get({sysDescr}, h); }),
                     SecurityError::credentialConflict);

        // The good Session is unaffected, and a second Session with the same keys shares the entry.
        REQUIRE(wait(context, [&](auto h) { goodSession.get({sysDescr}, h); }).has_value());
        auto twin = makeSession(context, good);
        REQUIRE(wait(context, [&](auto h) { twin.get({sysDescr}, h); }).has_value());
    }
}
