// SPDX-License-Identifier: MIT
#include <snmp_coro/error.hpp>

#include <boost/throw_exception.hpp>

#include <string>
#include <utility>
#include <variant>

namespace snmp_coro {
namespace {

std::string describe(const Error& error) {
    std::string out(toString(error.flavour()));
    out += ": ";
    std::visit([&out](auto code) { out += toString(code); }, error.code);
    if (!error.message.empty()) {
        out += " (";
        out += error.message;
        out += ')';
    }
    return out;
}

} // namespace

SnmpError::SnmpError(Error error)
    : std::runtime_error(describe(error)), m_error(std::move(error)) {}

void throw_exception_from_error(const Error& error, const boost::source_location& location) {
    boost::throw_exception(SnmpError(error), location);
}

std::string_view toString(ErrorFlavour value) noexcept {
    switch (value) {
    case ErrorFlavour::transport: return "transport";
    case ErrorFlavour::pduStatus: return "pduStatus";
    case ErrorFlavour::security: return "security";
    }
    return "unknown";
}

std::string_view toString(TransportError value) noexcept {
    switch (value) {
    case TransportError::timeout: return "timeout";
    case TransportError::sendFailed: return "sendFailed";
    case TransportError::aborted: return "aborted";
    case TransportError::limitExceeded: return "limitExceeded";
    }
    return "unknown";
}

std::string_view toString(PduError value) noexcept {
    switch (value) {
    case PduError::noError: return "noError";
    case PduError::tooBig: return "tooBig";
    case PduError::noSuchName: return "noSuchName";
    case PduError::badValue: return "badValue";
    case PduError::readOnly: return "readOnly";
    case PduError::genErr: return "genErr";
    case PduError::noAccess: return "noAccess";
    case PduError::wrongType: return "wrongType";
    case PduError::wrongLength: return "wrongLength";
    case PduError::wrongEncoding: return "wrongEncoding";
    case PduError::wrongValue: return "wrongValue";
    case PduError::noCreation: return "noCreation";
    case PduError::inconsistentValue: return "inconsistentValue";
    case PduError::resourceUnavailable: return "resourceUnavailable";
    case PduError::commitFailed: return "commitFailed";
    case PduError::undoFailed: return "undoFailed";
    case PduError::authorizationError: return "authorizationError";
    case PduError::notWritable: return "notWritable";
    case PduError::inconsistentName: return "inconsistentName";
    }
    return "unknown";
}

std::string_view toString(SecurityError value) noexcept {
    switch (value) {
    case SecurityError::unknownUser: return "unknownUser";
    case SecurityError::authFailure: return "authFailure";
    case SecurityError::unsupportedLevel: return "unsupportedLevel";
    case SecurityError::discoveryFailed: return "discoveryFailed";
    case SecurityError::decryptFailed: return "decryptFailed";
    case SecurityError::notInTimeWindow: return "notInTimeWindow";
    case SecurityError::credentialConflict: return "credentialConflict";
    case SecurityError::unexpectedReport: return "unexpectedReport";
    }
    return "unknown";
}

} // namespace snmp_coro
