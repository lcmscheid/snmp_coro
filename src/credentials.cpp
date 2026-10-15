// SPDX-License-Identifier: MIT
#include <snmp_coro/credentials.hpp>

#include <stdexcept>
#include <utility>

namespace snmp_coro {
namespace {

void checkUser(const std::string& user) {
    if (user.empty() || user.size() > Credentials::maxUserLength) {
        throw std::invalid_argument("USM user name must be 1 to 32 octets");
    }
}

void checkPassphrase(const std::string& passphrase, std::string_view what) {
    if (passphrase.size() < Credentials::minPassphraseLength) {
        throw std::invalid_argument(std::string(what) + " passphrase must be at least 8 octets");
    }
}

} // namespace

Credentials::Credentials(std::string user, SecurityLevel level, std::optional<Auth> auth,
                         std::optional<Priv> priv)
    : m_user(std::move(user)), m_level(level), m_auth(std::move(auth)), m_priv(std::move(priv)) {}

Credentials Credentials::noAuthNoPriv(std::string user) {
    checkUser(user);
    return {std::move(user), SecurityLevel::noAuthNoPriv, std::nullopt, std::nullopt};
}

Credentials Credentials::authNoPriv(std::string user, AuthProtocol protocol,
                                    std::string passphrase) {
    checkUser(user);
    checkPassphrase(passphrase, "auth");
    return {std::move(user), SecurityLevel::authNoPriv,
            Auth{.protocol = protocol, .passphrase = std::move(passphrase)}, std::nullopt};
}

Credentials Credentials::authPriv(std::string user, AuthProtocol authProtocol,
                                  std::string authPassphrase, PrivProtocol privProtocol,
                                  std::string privPassphrase) {
    checkUser(user);
    checkPassphrase(authPassphrase, "auth");
    checkPassphrase(privPassphrase, "priv");
    return {std::move(user), SecurityLevel::authPriv,
            Auth{.protocol = authProtocol, .passphrase = std::move(authPassphrase)},
            Priv{.protocol = privProtocol, .passphrase = std::move(privPassphrase)}};
}

std::string_view toString(SecurityLevel value) noexcept {
    switch (value) {
    case SecurityLevel::noAuthNoPriv: return "noAuthNoPriv";
    case SecurityLevel::authNoPriv: return "authNoPriv";
    case SecurityLevel::authPriv: return "authPriv";
    }
    return "unknown";
}

std::string_view toString(AuthProtocol value) noexcept {
    switch (value) {
    case AuthProtocol::md5: return "md5";
    case AuthProtocol::sha1: return "sha1";
    case AuthProtocol::sha224: return "sha224";
    case AuthProtocol::sha256: return "sha256";
    case AuthProtocol::sha384: return "sha384";
    case AuthProtocol::sha512: return "sha512";
    }
    return "unknown";
}

std::string_view toString(PrivProtocol value) noexcept {
    switch (value) {
    case PrivProtocol::des: return "des";
    case PrivProtocol::aes128: return "aes128";
    }
    return "unknown";
}

} // namespace snmp_coro
