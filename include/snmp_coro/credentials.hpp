// SPDX-License-Identifier: MIT
#pragma once

#include <snmp_coro/export.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace snmp_coro {

enum class SecurityLevel : std::uint8_t { noAuthNoPriv, authNoPriv, authPriv };

/// HMAC-MD5-96 and HMAC-SHA-96 (RFC 3414) and the HMAC-SHA-2 family (RFC 7860).
enum class AuthProtocol : std::uint8_t { md5, sha1, sha224, sha256, sha384, sha512 };

/// CBC-DES (RFC 3414) and CFB128-AES-128 (RFC 3826).
enum class PrivProtocol : std::uint8_t { des, aes128 };

/// USM credentials for one user. The named constructors make a missing key for the declared
/// security level unrepresentable; the remaining checks throw before net-snmp is touched (ADR
/// 0005).
class SNMP_CORO_EXPORT Credentials {
public:
    struct Auth {
        AuthProtocol protocol;
        std::string passphrase;

        bool operator==(const Auth&) const = default;
    };

    struct Priv {
        PrivProtocol protocol;
        std::string passphrase;

        bool operator==(const Priv&) const = default;
    };

    static constexpr std::size_t maxUserLength = 32;      ///< SnmpAdminString (RFC 3411).
    static constexpr std::size_t minPassphraseLength = 8; ///< RFC 3414 §11.2.

    /// @throws std::invalid_argument on an empty or over-long user name.
    [[nodiscard]] static Credentials noAuthNoPriv(std::string user);

    /// @throws std::invalid_argument on a bad user name or a passphrase shorter than 8 octets.
    [[nodiscard]] static Credentials authNoPriv(std::string user, AuthProtocol protocol,
                                                std::string passphrase);

    /// @throws std::invalid_argument on a bad user name or a passphrase shorter than 8 octets.
    [[nodiscard]] static Credentials authPriv(std::string user, AuthProtocol authProtocol,
                                              std::string authPassphrase, PrivProtocol privProtocol,
                                              std::string privPassphrase);

    [[nodiscard]] const std::string& user() const noexcept { return m_user; }

    [[nodiscard]] SecurityLevel level() const noexcept { return m_level; }

    /// Engaged for authNoPriv and authPriv.
    [[nodiscard]] const std::optional<Auth>& auth() const noexcept { return m_auth; }

    /// Engaged for authPriv.
    [[nodiscard]] const std::optional<Priv>& priv() const noexcept { return m_priv; }

    bool operator==(const Credentials&) const = default;

private:
    Credentials(std::string user, SecurityLevel level, std::optional<Auth> auth,
                std::optional<Priv> priv);

    std::string m_user;
    SecurityLevel m_level;
    std::optional<Auth> m_auth;
    std::optional<Priv> m_priv;
};

[[nodiscard]] SNMP_CORO_EXPORT std::string_view toString(SecurityLevel value) noexcept;
[[nodiscard]] SNMP_CORO_EXPORT std::string_view toString(AuthProtocol value) noexcept;
[[nodiscard]] SNMP_CORO_EXPORT std::string_view toString(PrivProtocol value) noexcept;

} // namespace snmp_coro
