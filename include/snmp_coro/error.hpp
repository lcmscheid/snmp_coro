// SPDX-License-Identifier: MIT
#pragma once

#include <snmp_coro/export.hpp>

#include <boost/assert/source_location.hpp>
#include <boost/system/result.hpp>

#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>

namespace snmp_coro {

/// The three error flavours from the glossary (ADR 0003). The enumerator order matches the
/// alternative order of `Error::Code`, which is what `Error::flavour()` relies on.
enum class ErrorFlavour : std::uint8_t { transport, pduStatus, security };

/// Error flavour "Transport error": the agent never produced a usable response.
enum class TransportError : std::uint8_t {
    timeout,    ///< No response after all retries.
    sendFailed, ///< The request could not be built or put on the wire.
    aborted,    ///< Cancelled by the caller, or the Session was destroyed while it was in flight.
    limitExceeded, ///< The response exceeded a client-side limit (Options::maxWalkVarbinds).
};

/// Error flavour "PDU error-status": the agent understood the request and refused it.
/// Values are the RFC 3416 error-status codes.
enum class PduError : std::int32_t { // NOLINT(performance-enum-size): the wire type is INTEGER
    noError = 0,
    tooBig = 1,
    noSuchName = 2,
    badValue = 3,
    readOnly = 4,
    genErr = 5,
    noAccess = 6,
    wrongType = 7,
    wrongLength = 8,
    wrongEncoding = 9,
    wrongValue = 10,
    noCreation = 11,
    inconsistentValue = 12,
    resourceUnavailable = 13,
    commitFailed = 14,
    undoFailed = 15,
    authorizationError = 16,
    notWritable = 17,
    inconsistentName = 18,
};

/// Error flavour "Security error": a USM-level failure (RFC 3414).
enum class SecurityError : std::uint8_t {
    unknownUser,      ///< usmStatsUnknownUserNames report.
    authFailure,      ///< usmStatsWrongDigests report: wrong auth passphrase or protocol.
    unsupportedLevel, ///< usmStatsUnsupportedSecLevels report: user not configured for this level.
    discoveryFailed,  ///< No engineID could be discovered, or usmStatsUnknownEngineIDs report.
    decryptFailed,    ///< usmStatsDecryptionErrors report (see ADR 0006 for when it is visible).
    notInTimeWindow,  ///< usmStatsNotInTimeWindows report that survived net-snmp's resend.
    credentialConflict, ///< Another live Session uses different keys for the same user on this
                        ///< engine.
    unexpectedReport,   ///< Any other Report PDU.
};

struct Error {
    using Code = std::variant<TransportError, PduError, SecurityError>;

    Code code;
    std::uint32_t index{0}; ///< PDU error-index (1-based varbind position); 0 when not applicable.
    std::string message;

    [[nodiscard]] ErrorFlavour flavour() const noexcept {
        return static_cast<ErrorFlavour>(code.index());
    }

    bool operator==(const Error&) const = default;
};

static_assert(std::variant_size_v<Error::Code> == 3);
static_assert(std::is_same_v<std::variant_alternative_t<0, Error::Code>, TransportError>);
static_assert(std::is_same_v<std::variant_alternative_t<1, Error::Code>, PduError>);
static_assert(std::is_same_v<std::variant_alternative_t<2, Error::Code>, SecurityError>);

/// The exception `Result<T>::value()` throws when it holds an `Error`.
class SNMP_CORO_EXPORT SnmpError : public std::runtime_error {
public:
    explicit SnmpError(Error error);

    [[nodiscard]] const Error& error() const noexcept { return m_error; }

private:
    Error m_error;
};

/// Expected-style result (ADR 0003). Only the interface subset shared with `std::expected` is
/// used inside the library so that a C++23 port is a one-line alias swap.
template <class T>
using Result = boost::system::result<T, Error>;

/// Found by ADL from `boost::system::result<T, Error>::value()`.
[[noreturn]] SNMP_CORO_EXPORT void
throw_exception_from_error( // NOLINT(readability-identifier-naming)
    const Error& error, const boost::source_location& location);

[[nodiscard]] SNMP_CORO_EXPORT std::string_view toString(ErrorFlavour value) noexcept;
[[nodiscard]] SNMP_CORO_EXPORT std::string_view toString(TransportError value) noexcept;
[[nodiscard]] SNMP_CORO_EXPORT std::string_view toString(PduError value) noexcept;
[[nodiscard]] SNMP_CORO_EXPORT std::string_view toString(SecurityError value) noexcept;

} // namespace snmp_coro
