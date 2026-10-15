// SPDX-License-Identifier: MIT
#pragma once

#include <snmp_coro/credentials.hpp>
#include <snmp_coro/error.hpp>
#include <snmp_coro/export.hpp>
#include <snmp_coro/oid.hpp>
#include <snmp_coro/options.hpp>
#include <snmp_coro/varbind.hpp>

#include <boost/asio/any_completion_handler.hpp>
#include <boost/asio/async_result.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>

#include <memory>
#include <utility>
#include <vector>

namespace snmp_coro {

/// Completion signature shared by every Session operation.
using VarbindsSignature = void(Result<std::vector<Varbind>>);

namespace detail {

class SessionImpl;

using VarbindsHandler = boost::asio::any_completion_handler<VarbindsSignature>;

enum class Command : std::uint8_t { get, getNext, getBulk };

// The type-erased boundary into session.cpp, where all net-snmp code lives (ADR 0005, ADR 0007).
SNMP_CORO_EXPORT void initiateRead(const std::shared_ptr<SessionImpl>& impl, Command command,
                                   std::vector<Oid> oids, VarbindsHandler handler);
SNMP_CORO_EXPORT void initiateSet(const std::shared_ptr<SessionImpl>& impl,
                                  std::vector<Varbind> varbinds, VarbindsHandler handler);
SNMP_CORO_EXPORT void initiateWalk(const std::shared_ptr<SessionImpl>& impl, Oid root,
                                   VarbindsHandler handler);

SNMP_CORO_EXPORT void validateOids(const std::vector<Oid>& oids);

} // namespace detail

/// A long-lived handle to one SNMPv3 agent under one set of USM credentials (glossary: Session).
///
/// Every operation is an Asio asynchronous operation with completion signature
/// `void(Result<std::vector<Varbind>>)`, so it accepts any completion token (ADR 0007):
///
///     auto r = co_await session.get({Oid{"1.3.6.1.2.1.1.5.0"}});        // deferred (default)
///     session.walk(Oid{"1.3.6.1.2.1.1"}, [](Result<std::vector<Varbind>> r) { ... });
///
/// Many operations may be in flight at once; they are multiplexed over one net-snmp session
/// (ADR 0001). The constructor performs no I/O: engineID discovery happens asynchronously on the
/// first operation (ADR 0006).
///
/// Threading: the io_context must be run by one thread (ADR 0001). Operations may be started
/// from any thread; their work is dispatched onto the io_context.
///
/// Destroying the Session completes every outstanding operation with TransportError::aborted.
class SNMP_CORO_EXPORT Session {
public:
    using executor_type = boost::asio::io_context::executor_type;

    /// Derives the USM master keys from @p credentials and keeps no copy of the passphrases:
    /// the caller may wipe or destroy @p credentials as soon as the constructor returns.
    /// @throws std::invalid_argument if @p target is unspecified or has port 0, or @p options is
    ///         out of range (see Options).
    Session(boost::asio::io_context& context, const boost::asio::ip::udp::endpoint& target,
            const Credentials& credentials, Options options = {});
    ~Session();

    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;
    Session(Session&& other) noexcept;
    Session& operator=(Session&& other) noexcept;

    [[nodiscard]] executor_type
    get_executor() const noexcept; // NOLINT(readability-identifier-naming)

    /// SNMP GetRequest. @throws std::invalid_argument if @p oids is empty.
    template <boost::asio::completion_token_for<VarbindsSignature> Token = boost::asio::deferred_t>
    auto get(std::vector<Oid> oids, Token&& token = {}) {
        return startRead(detail::Command::get, std::move(oids), std::forward<Token>(token));
    }

    /// SNMP GetNextRequest. @throws std::invalid_argument if @p oids is empty.
    template <boost::asio::completion_token_for<VarbindsSignature> Token = boost::asio::deferred_t>
    auto getNext(std::vector<Oid> oids, Token&& token = {}) {
        return startRead(detail::Command::getNext, std::move(oids), std::forward<Token>(token));
    }

    /// SNMP GetBulkRequest with non-repeaters 0 and max-repetitions Options::maxRepetitions.
    /// @throws std::invalid_argument if @p oids is empty.
    template <boost::asio::completion_token_for<VarbindsSignature> Token = boost::asio::deferred_t>
    auto getBulk(std::vector<Oid> oids, Token&& token = {}) {
        return startRead(detail::Command::getBulk, std::move(oids), std::forward<Token>(token));
    }

    /// SNMP SetRequest. @throws std::invalid_argument per detail::validateForSet.
    template <boost::asio::completion_token_for<VarbindsSignature> Token = boost::asio::deferred_t>
    auto set(std::vector<Varbind> varbinds, Token&& token = {}) {
        detail::validateForSet(varbinds);
        return boost::asio::async_initiate<Token, VarbindsSignature>(
            [impl = impl()](detail::VarbindsHandler handler, std::vector<Varbind> request) {
                detail::initiateSet(impl, std::move(request), std::move(handler));
            },
            token, std::move(varbinds));
    }

    /// Walk (glossary): repeated getBulk from @p root, collecting every varbind strictly beneath
    /// it in lexicographic order. Completes with PduError::genErr if the agent returns a
    /// non-increasing OID. A @p root with nothing beneath it yields an empty vector.
    template <boost::asio::completion_token_for<VarbindsSignature> Token = boost::asio::deferred_t>
    auto walk(Oid root, Token&& token = {}) {
        return boost::asio::async_initiate<Token, VarbindsSignature>(
            [impl = impl()](detail::VarbindsHandler handler, Oid subtree) {
                detail::initiateWalk(impl, std::move(subtree), std::move(handler));
            },
            token, std::move(root));
    }

private:
    template <class Token>
    auto startRead(detail::Command command, std::vector<Oid> oids, Token&& token) {
        detail::validateOids(oids);
        return boost::asio::async_initiate<Token, VarbindsSignature>(
            [impl = impl()](detail::VarbindsHandler handler, detail::Command kind,
                            std::vector<Oid> request) {
                detail::initiateRead(impl, kind, std::move(request), std::move(handler));
            },
            token, command, std::move(oids));
    }

    /// @throws std::logic_error on a moved-from Session.
    [[nodiscard]] const std::shared_ptr<detail::SessionImpl>& impl() const;

    executor_type m_executor;
    std::shared_ptr<detail::SessionImpl> m_impl;
};

} // namespace snmp_coro
