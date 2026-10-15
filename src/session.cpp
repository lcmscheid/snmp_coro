// SPDX-License-Identifier: MIT
//
// The single translation seam between snmp_coro and net-snmp (ADR 0005): this is the only file
// that includes net-snmp headers. Everything that touches net-snmp runs on the Session's
// io_context thread (ADR 0001); see ADR 0006 for engine discovery and USM user ownership.

#include <snmp_coro/session.hpp>

#include <boost/asio/append.hpp>
#include <boost/asio/associated_cancellation_slot.hpp>
#include <boost/asio/cancellation_state.hpp>
#include <boost/asio/cancellation_type.hpp>
#include <boost/asio/co_composed.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring> // explicit_bzero, strdup (POSIX)
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include <openssl/evp.h>

// net-snmp is a C library with a large macro surface; include it after everything else.
// clang-format off: net-snmp-config.h must precede every other net-snmp header.
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/library/large_fd_set.h>
// clang-format on

// The C API forces unions, pointer arithmetic, C arrays (and their decay), int<->pointer casts,
// malloc'd strings and mutable string buffers on us; those checks are disabled for this file only.
// NOLINTBEGIN(cppcoreguidelines-pro-type-union-access,cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-pro-type-reinterpret-cast,cppcoreguidelines-avoid-c-arrays,modernize-avoid-c-arrays,cppcoreguidelines-pro-type-const-cast,cppcoreguidelines-no-malloc,cppcoreguidelines-owning-memory,cppcoreguidelines-pro-bounds-array-to-pointer-decay,performance-no-int-to-ptr)

namespace snmp_coro::detail {

namespace asio = boost::asio;
using boost::asio::ip::udp;
using NetSnmpOid = ::oid;
using Varbinds = std::vector<Varbind>;

namespace {

// ---------------------------------------------------------------------------------------------
// Process-wide net-snmp state
// ---------------------------------------------------------------------------------------------

/// net-snmp has process-global configuration. snmp_coro owns it: no config files, no persistent
/// state written to /var/lib/snmp, and no MIB loading (ADR 0002: numeric OIDs only).
void ensureNetSnmpInitialised() {
    static const bool initialised = [] {
        netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_DONT_READ_CONFIGS, 1);
        netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_DISABLE_PERSISTENT_LOAD, 1);
        netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_DISABLE_PERSISTENT_SAVE, 1);
        static char noMibs[] = "mibs :"; // net-snmp copies the line
        netsnmp_config_remember(noMibs);
        init_snmp("snmp_coro");
        return true;
    }();
    static_cast<void>(initialised);
}

/// net-snmp keeps one USM user table per process, keyed by (engineID, user name), and silently
/// reuses an existing entry's keys when a new session names the same user. Left alone, a Session
/// with a wrong passphrase would authenticate with keys cached by an earlier one. The registry
/// tracks which live Sessions hold each entry (ADR 0006).
struct UsmKey {
    std::vector<u_char> engineId;
    std::string user;

    auto operator<=>(const UsmKey&) const = default;
};

struct UsmHolder {
    std::vector<u_char> fingerprint; // protocols + master keys of the holders
    std::size_t holders{0};
};

std::map<UsmKey, UsmHolder>& usmRegistry() {
    static std::map<UsmKey, UsmHolder> registry;
    return registry;
}

void forgetUsmUser(const UsmKey& key) noexcept {
    usmUser* user = usm_get_user(const_cast<u_char*>(key.engineId.data()), key.engineId.size(),
                                 const_cast<char*>(key.user.c_str()));
    if (user != nullptr) {
        usm_remove_user(user);
        usm_free_user(user);
    }
}

void wipe(std::vector<u_char>& bytes) noexcept {
    explicit_bzero(bytes.data(), bytes.size());
    bytes.clear();
}

// ---------------------------------------------------------------------------------------------
// Translation: snmp_coro <-> net-snmp
// ---------------------------------------------------------------------------------------------

struct ProtocolOid {
    NetSnmpOid* oid;
    std::size_t length;
};

ProtocolOid toNetSnmp(AuthProtocol protocol) {
    switch (protocol) {
    case AuthProtocol::md5:
        return {.oid = usmHMACMD5AuthProtocol, .length = OID_LENGTH(usmHMACMD5AuthProtocol)};
    case AuthProtocol::sha1:
        return {.oid = usmHMACSHA1AuthProtocol, .length = OID_LENGTH(usmHMACSHA1AuthProtocol)};
    case AuthProtocol::sha224:
        return {.oid = usmHMAC128SHA224AuthProtocol,
                .length = OID_LENGTH(usmHMAC128SHA224AuthProtocol)};
    case AuthProtocol::sha256:
        return {.oid = usmHMAC192SHA256AuthProtocol,
                .length = OID_LENGTH(usmHMAC192SHA256AuthProtocol)};
    case AuthProtocol::sha384:
        return {.oid = usmHMAC256SHA384AuthProtocol,
                .length = OID_LENGTH(usmHMAC256SHA384AuthProtocol)};
    case AuthProtocol::sha512:
        return {.oid = usmHMAC384SHA512AuthProtocol,
                .length = OID_LENGTH(usmHMAC384SHA512AuthProtocol)};
    }
    throw std::invalid_argument("unknown AuthProtocol");
}

ProtocolOid toNetSnmp(PrivProtocol protocol) {
    switch (protocol) {
    case PrivProtocol::des:
        return {.oid = usmDESPrivProtocol, .length = OID_LENGTH(usmDESPrivProtocol)};
    case PrivProtocol::aes128:
        return {.oid = usmAESPrivProtocol, .length = OID_LENGTH(usmAESPrivProtocol)};
    }
    throw std::invalid_argument("unknown PrivProtocol");
}

const EVP_MD* digestOf(AuthProtocol protocol) {
    switch (protocol) {
    case AuthProtocol::md5: return EVP_md5();
    case AuthProtocol::sha1: return EVP_sha1();
    case AuthProtocol::sha224: return EVP_sha224();
    case AuthProtocol::sha256: return EVP_sha256();
    case AuthProtocol::sha384: return EVP_sha384();
    case AuthProtocol::sha512: return EVP_sha512();
    }
    throw std::invalid_argument("unknown AuthProtocol");
}

/// RFC 3414 A.2 password-to-key (Ku), generalised to SHA-2 by RFC 7860: hash 1 MiB of the
/// repeated passphrase. The same algorithm as net-snmp's generate_Ku, done with OpenSSL alone so
/// the Session constructor can run it on any thread without touching net-snmp (ADR 0001).
/// @returns the key length written to @p key.
std::size_t passwordToKey(AuthProtocol protocol, const std::string& passphrase,
                          std::span<u_char> key) {
    constexpr std::size_t expandedLength = 1'048'576;
    const EVP_MD* digest = digestOf(protocol);
    const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(EVP_MD_CTX_new(),
                                                                          &EVP_MD_CTX_free);
    if (digest == nullptr || context == nullptr ||
        EVP_DigestInit_ex(context.get(), digest, nullptr) != 1 ||
        static_cast<std::size_t>(EVP_MD_get_size(digest)) > key.size()) {
        throw std::invalid_argument("auth protocol " + std::string(toString(protocol)) +
                                    " is not supported by the linked OpenSSL");
    }
    std::array<u_char, 64> block{};
    std::size_t index = 0;
    bool ok = true;
    for (std::size_t done = 0; done < expandedLength; done += block.size()) {
        for (auto& byte : block) {
            byte = static_cast<u_char>(passphrase[index++ % passphrase.size()]);
        }
        ok = ok && EVP_DigestUpdate(context.get(), block.data(), block.size()) == 1;
    }
    explicit_bzero(block.data(), block.size());
    unsigned int length = 0;
    if (!ok || EVP_DigestFinal_ex(context.get(), key.data(), &length) != 1) {
        throw std::invalid_argument("could not derive the " + std::string(toString(protocol)) +
                                    " key");
    }
    return length;
}

int toNetSnmp(SecurityLevel level) {
    switch (level) {
    case SecurityLevel::noAuthNoPriv: return SNMP_SEC_LEVEL_NOAUTH;
    case SecurityLevel::authNoPriv: return SNMP_SEC_LEVEL_AUTHNOPRIV;
    case SecurityLevel::authPriv: return SNMP_SEC_LEVEL_AUTHPRIV;
    }
    throw std::invalid_argument("unknown SecurityLevel");
}

std::size_t toNetSnmp(const Oid& oid, std::array<NetSnmpOid, MAX_OID_LEN>& out) {
    const auto subids = oid.subids();
    std::ranges::copy(subids, out.begin());
    return subids.size();
}

Oid fromNetSnmp(const NetSnmpOid* subids, std::size_t length) {
    std::vector<std::uint32_t> converted(length);
    for (std::size_t i = 0; i < length; ++i) {
        if (subids[i] > std::numeric_limits<std::uint32_t>::max()) {
            throw std::invalid_argument("agent returned a sub-identifier above 2^32-1");
        }
        converted[i] = static_cast<std::uint32_t>(subids[i]);
    }
    return Oid(std::span<const std::uint32_t>(converted));
}

std::string bytesOf(const netsnmp_variable_list& variable) {
    if (variable.val.string == nullptr) {
        return {};
    }
    return {reinterpret_cast<const char*>(variable.val.string), variable.val_len};
}

std::uint64_t unsigned32Of(const netsnmp_variable_list& variable) {
    return static_cast<std::uint32_t>(*variable.val.integer);
}

Varbind fromNetSnmp(const netsnmp_variable_list& variable) {
    Oid name = fromNetSnmp(variable.name, variable.name_length);
    switch (variable.type) {
    case ASN_NULL: return Varbind::null(std::move(name));
    case ASN_INTEGER:
        return {.oid = std::move(name),
                .type = AsnType::integer,
                .value = std::int64_t{*variable.val.integer}};
    case ASN_OCTET_STR:
        return {.oid = std::move(name), .type = AsnType::octetString, .value = bytesOf(variable)};
    case ASN_OPAQUE:
        return {.oid = std::move(name), .type = AsnType::opaque, .value = bytesOf(variable)};
    case ASN_OBJECT_ID:
        return {.oid = std::move(name),
                .type = AsnType::oid,
                .value = fromNetSnmp(variable.val.objid, variable.val_len / sizeof(NetSnmpOid))};
    case ASN_IPADDRESS: {
        boost::asio::ip::address_v4::bytes_type bytes{};
        if (variable.val_len != bytes.size()) {
            return {.oid = std::move(name), .type = AsnType::opaque, .value = bytesOf(variable)};
        }
        std::memcpy(bytes.data(), variable.val.string, bytes.size());
        return {.oid = std::move(name),
                .type = AsnType::ipAddress,
                .value = boost::asio::ip::address_v4(bytes)};
    }
    case ASN_COUNTER:
        return {
            .oid = std::move(name), .type = AsnType::counter32, .value = unsigned32Of(variable)};
    case ASN_GAUGE: // == ASN_UNSIGNED
    case ASN_UINTEGER:
        return {.oid = std::move(name), .type = AsnType::gauge, .value = unsigned32Of(variable)};
    case ASN_TIMETICKS:
        return {
            .oid = std::move(name), .type = AsnType::timeticks, .value = unsigned32Of(variable)};
    case ASN_COUNTER64: {
        const auto& c64 = *variable.val.counter64;
        const std::uint64_t value = (std::uint64_t{static_cast<std::uint32_t>(c64.high)} << 32U) |
                                    static_cast<std::uint32_t>(c64.low);
        return {.oid = std::move(name), .type = AsnType::counter64, .value = value};
    }
    case SNMP_NOSUCHOBJECT:
        return {.oid = std::move(name),
                .type = AsnType::null,
                .value = NoSuch{NoSuch::Kind::noSuchObject}};
    case SNMP_NOSUCHINSTANCE:
        return {.oid = std::move(name),
                .type = AsnType::null,
                .value = NoSuch{NoSuch::Kind::noSuchInstance}};
    case SNMP_ENDOFMIBVIEW:
        return {.oid = std::move(name),
                .type = AsnType::null,
                .value = NoSuch{NoSuch::Kind::endOfMibView}};
    default: return {.oid = std::move(name), .type = AsnType::opaque, .value = bytesOf(variable)};
    }
}

u_char unsigned32Tag(AsnType type) {
    switch (type) {
    case AsnType::counter32: return ASN_COUNTER;
    case AsnType::timeticks: return ASN_TIMETICKS;
    default: return ASN_GAUGE;
    }
}

/// Appends @p varbind to @p pdu. Values were validated by validateForSet before initiation.
bool addVariable(netsnmp_pdu& pdu, const Varbind& varbind) {
    std::array<NetSnmpOid, MAX_OID_LEN> name{};
    const std::size_t nameLength = toNetSnmp(varbind.oid, name);
    const auto add = [&](u_char type, const void* value, std::size_t valueSize) {
        return snmp_pdu_add_variable(&pdu, name.data(), nameLength, type, value, valueSize) !=
               nullptr;
    };
    switch (varbind.type) {
    case AsnType::null: return snmp_add_null_var(&pdu, name.data(), nameLength) != nullptr;
    case AsnType::integer: {
        const long value = static_cast<long>(std::get<std::int64_t>(varbind.value));
        return add(ASN_INTEGER, &value, sizeof value);
    }
    case AsnType::octetString:
    case AsnType::opaque: {
        const auto& value = std::get<std::string>(varbind.value);
        return add(varbind.type == AsnType::opaque ? ASN_OPAQUE : ASN_OCTET_STR, value.data(),
                   value.size());
    }
    case AsnType::oid: {
        std::array<NetSnmpOid, MAX_OID_LEN> value{};
        const std::size_t length = toNetSnmp(std::get<Oid>(varbind.value), value);
        return add(ASN_OBJECT_ID, value.data(), length * sizeof(NetSnmpOid));
    }
    case AsnType::ipAddress: {
        const auto bytes = std::get<boost::asio::ip::address_v4>(varbind.value).to_bytes();
        return add(ASN_IPADDRESS, bytes.data(), bytes.size());
    }
    case AsnType::counter32:
    case AsnType::gauge:
    case AsnType::timeticks: {
        const u_long value = std::get<std::uint64_t>(varbind.value);
        return add(unsigned32Tag(varbind.type), &value, sizeof value);
    }
    case AsnType::counter64: {
        const auto value = std::get<std::uint64_t>(varbind.value);
        counter64 c64{};
        c64.high = value >> 32U;
        c64.low = value & 0xFFFF'FFFFU;
        return add(ASN_COUNTER64, &c64, sizeof c64);
    }
    }
    return false;
}

Error securityErrorFromReport(netsnmp_pdu& report) {
    const int type = snmpv3_get_report_type(&report);
    SecurityError code = SecurityError::unexpectedReport;
    switch (type) {
    case SNMPERR_UNKNOWN_USER_NAME: code = SecurityError::unknownUser; break;
    case SNMPERR_AUTHENTICATION_FAILURE: code = SecurityError::authFailure; break;
    case SNMPERR_UNSUPPORTED_SEC_LEVEL: code = SecurityError::unsupportedLevel; break;
    case SNMPERR_UNKNOWN_ENG_ID: code = SecurityError::discoveryFailed; break;
    case SNMPERR_DECRYPTION_ERR: code = SecurityError::decryptFailed; break;
    case SNMPERR_NOT_IN_TIME_WINDOW: code = SecurityError::notInTimeWindow; break;
    default: break;
    }
    return Error{.code = code, .message = snmp_api_errstring(type)};
}

Result<Varbinds> fromNetSnmp(netsnmp_pdu& pdu) noexcept {
    try {
        if (pdu.command == SNMP_MSG_REPORT) {
            return securityErrorFromReport(pdu);
        }
        if (pdu.errstat != SNMP_ERR_NOERROR) {
            return Error{.code = static_cast<PduError>(pdu.errstat),
                         .index = static_cast<std::uint32_t>(std::max(0L, pdu.errindex)),
                         .message = snmp_errstring(static_cast<int>(pdu.errstat))};
        }
        Varbinds out;
        for (const netsnmp_variable_list* v = pdu.variables; v != nullptr; v = v->next_variable) {
            out.push_back(fromNetSnmp(*v));
        }
        return out;
    } catch (const std::exception& e) {
        // Nothing may propagate through net-snmp's C stack frames.
        return Error{.code = PduError::genErr,
                     .message = std::string("malformed response: ") + e.what()};
    } catch (...) {
        return Error{.code = PduError::genErr, .message = "malformed response"};
    }
}

/// Runs @p fetch, one of net-snmp's error-text getters, and takes ownership of its malloc'd text.
template <typename Fetch>
std::string netSnmpError(Fetch fetch) {
    int libError = 0;
    int sysError = 0;
    char* text = nullptr;
    fetch(&libError, &sysError, &text);
    std::string message = text != nullptr ? text : "unknown net-snmp error";
    std::free(text);
    return message;
}

std::string sessionError(void* sessp) {
    return netSnmpError(
        [sessp](int* lib, int* sys, char** text) { snmp_sess_error(sessp, lib, sys, text); });
}

std::string openError(netsnmp_session& config) {
    return netSnmpError(
        [&config](int* lib, int* sys, char** text) { snmp_error(&config, lib, sys, text); });
}

std::string peername(const udp::endpoint& target) {
    const auto& address = target.address();
    const auto port = std::to_string(target.port());
    return address.is_v6() ? "udp6:[" + address.to_string() + "]:" + port
                           : "udp:" + address.to_string() + ":" + port;
}

} // namespace

// ---------------------------------------------------------------------------------------------
// Channel: one net-snmp single-session handle driven by Asio (ADR 0001)
// ---------------------------------------------------------------------------------------------

class SessionImpl;

namespace {

/// Wraps a net-snmp session's UDP socket in a stream_descriptor (wait-only; net-snmp does the
/// reading) and drives retransmissions with a steady_timer armed from snmp_sess_select_info2.
/// I/O is armed only while the owner reports work, so io_context::run() can return.
class Channel : public std::enable_shared_from_this<Channel> {
    struct Key {};

public:
    using Executor = asio::io_context::executor_type;

    Channel(Key /*key*/, const Executor& executor, void* sessp, int fd,
            std::weak_ptr<SessionImpl> owner)
        : m_sessp(sessp),
          m_descriptor(executor, fd),
          m_timer(executor),
          m_owner(std::move(owner)) {}

    Channel(const Channel&) = delete;
    Channel& operator=(const Channel&) = delete;
    Channel(Channel&&) = delete;
    Channel& operator=(Channel&&) = delete;
    ~Channel() { close(); }

    /// @returns nullptr and sets @p error if net-snmp cannot open the session.
    static std::shared_ptr<Channel> open(const Executor& executor, netsnmp_session& config,
                                         std::weak_ptr<SessionImpl> owner, std::string& error) {
        void* sessp = snmp_sess_open(&config);
        if (sessp == nullptr) {
            error = openError(config);
            return nullptr;
        }
        // snmp_sess_open clears SNMP_FLAGS_DONT_PROBE on its internal copy. Without it,
        // snmp_sess_async_send runs a *synchronous* engineID probe whenever the session has no
        // engineID, blocking the io_context thread for timeout * (retries + 1) (ADR 0006).
        snmp_sess_session(sessp)->flags |= SNMP_FLAGS_DONT_PROBE;
        const netsnmp_transport* transport = snmp_sess_transport(sessp);
        if (transport == nullptr || transport->sock < 0) {
            snmp_sess_close(sessp);
            error = "net-snmp session has no socket";
            return nullptr;
        }
        try {
            return std::make_shared<Channel>(Key{}, executor, sessp, transport->sock,
                                             std::move(owner));
        } catch (...) {
            snmp_sess_close(sessp);
            throw;
        }
    }

    [[nodiscard]] void* handle() const noexcept { return m_sessp; }

    void setActive(bool active) {
        m_active = active;
        if (m_sessp == nullptr) {
            return;
        }
        if (!active) {
            boost::system::error_code ignored;
            static_cast<void>(m_descriptor.cancel(ignored));
            disarmTimer();
            return;
        }
        armRead();
        // Every request of a session shares one timeout, so a request queued later never expires
        // before the deadline already armed; a deadline that moved later only makes the timer fire
        // early, which re-arms it. Re-querying net-snmp (which walks its request list) on every
        // submit and response is therefore unnecessary.
        if (!m_timerArmed) {
            armTimer();
        }
    }

    void close() noexcept {
        if (m_sessp == nullptr) {
            return;
        }
        try {
            boost::system::error_code ignored;
            static_cast<void>(m_descriptor.cancel(ignored));
            static_cast<void>(m_descriptor.release()); // net-snmp owns and closes the socket
            disarmTimer();
        } catch (const boost::system::system_error&) { // NOLINT(bugprone-empty-catch)
            // Failing to cancel waits is harmless: their handlers see m_sessp == nullptr.
        }
        snmp_sess_close(m_sessp);
        m_sessp = nullptr;
    }

private:
    void notifyOwner();

    void armRead() {
        if (m_readArmed) {
            return;
        }
        m_readArmed = true;
        m_descriptor.async_wait(asio::posix::descriptor_base::wait_read,
                                [self = shared_from_this()](const boost::system::error_code& ec) {
                                    self->m_readArmed = false;
                                    if (self->m_sessp == nullptr) {
                                        return;
                                    }
                                    if (ec) {
                                        // Cancelled by setActive(false); re-arm if work arrived in
                                        // the meantime.
                                        if (ec == asio::error::operation_aborted &&
                                            self->m_active) {
                                            self->armRead();
                                        }
                                        return;
                                    }
                                    const int fd = self->m_descriptor.native_handle();
                                    netsnmp_large_fd_set fds;
                                    netsnmp_large_fd_set_init(&fds, fd + 1);
                                    NETSNMP_LARGE_FD_SET(fd, &fds);
                                    snmp_sess_read2(self->m_sessp, &fds);
                                    netsnmp_large_fd_set_cleanup(&fds);
                                    self->notifyOwner();
                                });
    }

    void disarmTimer() {
        ++m_timerGeneration; // a wait that already completed must not act or clear m_timerArmed
        m_timerArmed = false;
        m_timer.cancel();
    }

    void armTimer() {
        int fdCount = 0;
        int block = 1;
        timeval timeout{};
        netsnmp_large_fd_set fds;
        netsnmp_large_fd_set_init(&fds, FD_SETSIZE);
        snmp_sess_select_info2(m_sessp, &fdCount, &fds, &timeout, &block);
        netsnmp_large_fd_set_cleanup(&fds);
        if (block != 0) {
            disarmTimer();
            return;
        }
        const std::uint64_t generation = ++m_timerGeneration;
        m_timerArmed = true;
        m_timer.expires_after(std::chrono::seconds(timeout.tv_sec) +
                              std::chrono::microseconds(timeout.tv_usec));
        m_timer.async_wait(
            [self = shared_from_this(), generation](const boost::system::error_code& ec) {
                if (generation != self->m_timerGeneration) {
                    return; // superseded by a re-arm or a disarm
                }
                self->m_timerArmed = false;
                if (ec || self->m_sessp == nullptr) {
                    return;
                }
                snmp_sess_timeout(self->m_sessp);
                self->notifyOwner();
            });
    }

    void* m_sessp;
    asio::posix::stream_descriptor m_descriptor;
    asio::steady_timer m_timer;
    std::weak_ptr<SessionImpl> m_owner;
    bool m_active{false};
    bool m_readArmed{false};
    bool m_timerArmed{false};
    std::uint64_t m_timerGeneration{0};
};

int requestCallback(int operation, netsnmp_session* session, int requestId, netsnmp_pdu* pdu,
                    void* magic) noexcept;
int probeCallback(int operation, netsnmp_session* session, int requestId, netsnmp_pdu* pdu,
                  void* magic) noexcept;

} // namespace

// ---------------------------------------------------------------------------------------------
// SessionImpl
// ---------------------------------------------------------------------------------------------

namespace {
enum class RequestKind : std::uint8_t { get, getNext, getBulk, set };

/// What net-snmp does with a request after delivering a Report for it (see
/// _sess_process_packet_handle_pdu in net-snmp 5.9.4's snmp_api.c).
enum class ReportAction : std::uint8_t {
    none,         ///< not a Report, or one that ends the request
    resend,       ///< notInTimeWindow: net-snmp resends with corrected time, or, once out of
                  ///< retries, follows up with OP_SEC_ERROR and then drops the request
    engineChanged ///< unknownEngineID on an established session: the agent's engineID changed
};
} // namespace

class SessionImpl : public std::enable_shared_from_this<SessionImpl> {
public:
    using Executor = asio::io_context::executor_type;

    SessionImpl(Executor executor, const udp::endpoint& target, const Credentials& credentials,
                Options options)
        : m_executor(std::move(executor)),
          m_peername(peername(target)),
          m_identity{.user = credentials.user(),
                     .level = credentials.level(),
                     .auth = credentials.auth() ? std::optional(credentials.auth()->protocol)
                                                : std::nullopt,
                     .priv = credentials.priv() ? std::optional(credentials.priv()->protocol)
                                                : std::nullopt},
          m_options(options) {
        if (target.address().is_unspecified() || target.port() == 0) {
            throw std::invalid_argument("target endpoint must have a specific address and port");
        }
        // net-snmp stores the timeout as microseconds in a long and adds it to a timeval's
        // tv_usec (up to 999999), so larger values overflow (signed overflow: undefined).
        constexpr auto maxTimeout = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::microseconds(std::numeric_limits<long>::max() - 999'999));
        if (options.timeout <= std::chrono::milliseconds::zero() || options.timeout > maxTimeout) {
            throw std::invalid_argument("Options::timeout must be positive and at most " +
                                        std::to_string(maxTimeout.count()) + " ms");
        }
        if (options.retries > static_cast<std::uint32_t>(std::numeric_limits<int>::max())) {
            throw std::invalid_argument("Options::retries out of range");
        }
        if (options.maxRepetitions == 0 ||
            options.maxRepetitions >
                static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max())) {
            throw std::invalid_argument("Options::maxRepetitions must be in [1, 2^31)");
        }
        if (options.maxWalkVarbinds == 0) {
            throw std::invalid_argument("Options::maxWalkVarbinds must be at least 1");
        }
        deriveMasterKeys(credentials);
    }

    SessionImpl(const SessionImpl&) = delete;
    SessionImpl& operator=(const SessionImpl&) = delete;
    SessionImpl(SessionImpl&&) = delete;
    SessionImpl& operator=(SessionImpl&&) = delete;

    ~SessionImpl() {
        // Normally shutdown() already ran. If it did not (the io_context was torn down first),
        // release net-snmp resources; pending handlers are destroyed without being invoked.
        // Drop them *before* closing: snmp_sess_close runs every queued request's callback with
        // OP_TIMED_OUT, which would otherwise post completions to an io_context being destroyed.
        m_pending.clear();
        m_sent = 0;
        closeChannels();
        releaseUsm();
        wipe(m_fingerprint);
        explicit_bzero(m_authKey.data(), m_authKey.size());
        explicit_bzero(m_privKey.data(), m_privKey.size());
    }

    [[nodiscard]] Executor executor() const noexcept { return m_executor; }

    [[nodiscard]] const Options& options() const noexcept { return m_options; }

    /// Must run on the io_context thread.
    void submit(RequestKind kind, Varbinds varbinds, VarbindsHandler handler) {
        if (m_state == State::closed) {
            postCompletion(std::move(handler),
                           Error{.code = TransportError::aborted, .message = "session destroyed"});
            return;
        }
        const std::uint64_t id = m_nextId++;
        auto slot = asio::get_associated_cancellation_slot(handler);
        if (slot.is_connected()) {
            slot.assign(
                [weak = weak_from_this(), id, executor = m_executor](asio::cancellation_type type) {
                    if (type == asio::cancellation_type::none) {
                        return;
                    }
                    // Never complete from inside the slot handler: completing clears the slot.
                    asio::post(executor, [weak, id] {
                        if (auto self = weak.lock()) {
                            self->abandon(id);
                            self->updateActivity();
                        }
                    });
                });
        }
        m_pending.emplace(id, Pending{.kind = kind,
                                      .varbinds = std::move(varbinds),
                                      .handler = std::move(handler),
                                      .sent = false,
                                      .deferredReport = std::nullopt});

        switch (m_state) {
        case State::idle: startDiscovery(); break;
        case State::discovering: break; // queued; sent when discovery finishes
        case State::ready:
            if (!m_rediscover) {
                send(id);
            } // else queued; sent after rediscovery (reconcileChannel)
            break;
        case State::closed: break;
        }
        updateActivity();
    }

    /// Completes every outstanding operation with TransportError::aborted and releases net-snmp.
    void shutdown() {
        if (m_state == State::closed) {
            return;
        }
        m_state = State::closed;
        failAll(Error{.code = TransportError::aborted, .message = "session destroyed"});
        closeChannels();
        releaseUsm();
    }

    /// Called by a Channel after net-snmp processed input or a timeout (outside net-snmp frames).
    void onChannelActivity(const Channel& channel) {
        if (m_probe && &channel == m_probe.get() && m_probeOutcome) {
            finishDiscovery();
        }
        updateActivity();
    }

    /// net-snmp callback for a request (inside snmp_sess_read2 / snmp_sess_timeout).
    // noexcept on purpose: nothing may unwind through net-snmp's C frames, so an allocation
    // failure while completing terminates instead.
    // NOLINTNEXTLINE(bugprone-exception-escape)
    void onResponse(std::uint64_t id, int operation, netsnmp_pdu* pdu,
                    ReportAction report) noexcept {
        if (report == ReportAction::engineChanged) {
            m_rediscover = true; // acted on by reconcileChannel, outside net-snmp's frames
        }
        if (m_abandoned.contains(id)) {
            // Cancelled after it was sent: only track whether net-snmp still holds the request.
            const bool stillQueued = operation == NETSNMP_CALLBACK_OP_RESEND ||
                                     (operation == NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE &&
                                      report == ReportAction::resend);
            if (!stillQueued) {
                m_abandoned.erase(id);
            }
            return;
        }
        auto it = m_pending.find(id);
        if (it == m_pending.end()) {
            return; // already completed or aborted
        }
        switch (operation) {
        case NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE:
            // net-snmp 5.9.4 dereferences the PDU before calling, so it is never null here; if
            // another version passes none, net-snmp has dropped the request: fail, never hang.
            if (pdu == nullptr) {
                complete(id, Error{.code = PduError::genErr,
                                   .message = "net-snmp delivered a response without a PDU"});
            } else if (report == ReportAction::resend) {
                // net-snmp resends the request; its outcome is the operation's. Keep the Report in
                // case net-snmp is out of retries and follows up with OP_SEC_ERROR instead.
                it->second.deferredReport = securityErrorFromReport(*pdu);
            } else if (report == ReportAction::engineChanged) {
                Error error = securityErrorFromReport(*pdu);
                error.message += "; the agent's engineID changed and will be rediscovered";
                complete(id, std::move(error));
            } else {
                complete(id, fromNetSnmp(*pdu));
            }
            break;
        case NETSNMP_CALLBACK_OP_SEC_ERROR:
            // Follows a Report already handled in RECEIVED_MESSAGE, except after a deferred
            // notInTimeWindow Report: then net-snmp is out of retries and drops the request.
            if (auto& deferred = it->second.deferredReport) {
                Error error = std::move(*deferred);
                complete(id, std::move(error));
            }
            break;
        case NETSNMP_CALLBACK_OP_TIMED_OUT:
            // Also what an engineID change looks like: net-snmp drops the agent's unknownEngineID
            // Report, finding no USM user for the new engine. Verify the engine before going on.
            m_rediscover = true;
            complete(id, Error{.code = TransportError::timeout,
                               .message = "no response after " + std::to_string(m_options.retries) +
                                          " retries"});
            break;
        case NETSNMP_CALLBACK_OP_SEND_FAILED:
            complete(id, Error{.code = TransportError::sendFailed,
                               .message = "net-snmp could not send the request"});
            break;
        case NETSNMP_CALLBACK_OP_DISCONNECT:
            complete(id,
                     Error{.code = TransportError::aborted, .message = "transport disconnected"});
            break;
        default: break; // RESEND is informational
        }
    }

    /// net-snmp callback for the engineID discovery probe.
    void onProbeResponse(int operation, netsnmp_pdu* pdu) noexcept {
        if (m_probeOutcome) {
            return;
        }
        switch (operation) {
        case NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE:
            if (pdu != nullptr && pdu->securityEngineIDLen > 0) {
                m_probeOutcome.emplace(std::vector<u_char>(
                    pdu->securityEngineID, pdu->securityEngineID + pdu->securityEngineIDLen));
            } else {
                m_probeOutcome.emplace(Error{.code = SecurityError::discoveryFailed,
                                             .message = "discovery reply carried no engineID"});
            }
            break;
        case NETSNMP_CALLBACK_OP_TIMED_OUT:
            m_probeOutcome.emplace(
                Error{.code = TransportError::timeout, .message = "engineID discovery timed out"});
            break;
        case NETSNMP_CALLBACK_OP_SEND_FAILED:
        case NETSNMP_CALLBACK_OP_DISCONNECT:
            m_probeOutcome.emplace(Error{.code = TransportError::sendFailed,
                                         .message = "engineID discovery probe could not be sent"});
            break;
        default: break; // SEC_ERROR precedes the Report we are waiting for; RESEND is informational
        }
    }

private:
    enum class State : std::uint8_t { idle, discovering, ready, closed };

    struct Pending {
        RequestKind kind;
        Varbinds varbinds;
        VarbindsHandler handler;
        bool sent; ///< queued in net-snmp
        std::optional<Error> deferredReport;
    };

    /// The only place the passphrases are read. Only the derived master keys are kept, so the
    /// Session never holds a copy of a passphrase.
    void deriveMasterKeys(const Credentials& credentials) {
        m_fingerprint.push_back(static_cast<u_char>(credentials.level()));
        if (const auto& auth = credentials.auth()) {
            m_authKeyLength = passwordToKey(auth->protocol, auth->passphrase, m_authKey);
            m_fingerprint.push_back(static_cast<u_char>(auth->protocol));
            m_fingerprint.insert(m_fingerprint.end(), m_authKey.begin(),
                                 m_authKey.begin() + static_cast<std::ptrdiff_t>(m_authKeyLength));
        }
        const auto& authForPriv = credentials.auth();
        if (const auto& priv = credentials.priv(); priv && authForPriv) {
            // RFC 3414 derives the privacy key with the *authentication* hash.
            m_privKeyLength = passwordToKey(authForPriv->protocol, priv->passphrase, m_privKey);
            m_fingerprint.push_back(static_cast<u_char>(priv->protocol));
            m_fingerprint.insert(m_fingerprint.end(), m_privKey.begin(),
                                 m_privKey.begin() + static_cast<std::ptrdiff_t>(m_privKeyLength));
        }
    }

    void baseConfig(netsnmp_session& config) {
        snmp_sess_init(&config);
        config.version = SNMP_VERSION_3;
        config.peername = m_peername.data();
        config.timeout =
            std::chrono::duration_cast<std::chrono::microseconds>(m_options.timeout).count();
        config.retries = static_cast<int>(m_options.retries);
        config.flags |= SNMP_FLAGS_DONT_PROBE; // never block in snmp_sess_open (ADR 0006)
        config.callback_magic = this;
    }

    void startDiscovery() {
        ensureNetSnmpInitialised();
        m_state = State::discovering;
        m_probeOutcome.reset();

        netsnmp_session config{};
        baseConfig(config);
        static char emptyName[] = "";
        config.securityName = emptyName;
        config.securityNameLen = 0;
        config.securityLevel = SNMP_SEC_LEVEL_NOAUTH;

        std::string error;
        m_probe = Channel::open(m_executor, config, weak_from_this(), error);
        if (!m_probe) {
            m_state = State::idle;
            failAll(Error{.code = TransportError::sendFailed,
                          .message = "cannot open probe session: " + error});
            return;
        }

        // RFC 3414 §4: an unauthenticated request with an empty user elicits a Report that
        // carries the authoritative engineID.
        netsnmp_pdu* pdu = snmp_pdu_create(SNMP_MSG_GET);
        pdu->version = SNMP_VERSION_3;
        pdu->securityModel = SNMP_SEC_MODEL_USM;
        pdu->securityLevel = SNMP_SEC_LEVEL_NOAUTH;
        pdu->securityName = strdup("");
        pdu->securityNameLen = 0;
        if (snmp_sess_async_send(m_probe->handle(), pdu, &probeCallback, nullptr) == 0) {
            error = sessionError(m_probe->handle());
            snmp_free_pdu(pdu);
            m_probe->close();
            m_probe.reset();
            m_state = State::idle;
            failAll(Error{.code = TransportError::sendFailed,
                          .message = "cannot send discovery probe: " + error});
        }
    }

    void finishDiscovery() {
        if (!m_probeOutcome) {
            return;
        }
        auto outcome = std::move(*m_probeOutcome);
        m_probeOutcome.reset();
        m_probe->close();
        m_probe.reset();

        if (const auto* error = std::get_if<Error>(&outcome)) {
            m_state = State::idle;
            failAll(*error);
            return;
        }
        auto& engineId = std::get<std::vector<u_char>>(outcome);

        UsmKey key{.engineId = engineId, .user = m_identity.user};
        auto& registry = usmRegistry();
        auto entry = registry.find(key);
        if (entry != registry.end() && entry->second.holders > 0 &&
            entry->second.fingerprint != m_fingerprint) {
            m_state = State::idle;
            failAll(Error{.code = SecurityError::credentialConflict,
                          .message = "another live Session uses different keys for user '" +
                                     m_identity.user + "' on this engine"});
            return;
        }
        if (entry == registry.end() || entry->second.holders == 0) {
            forgetUsmUser(key); // drop keys cached by a Session that no longer exists
            if (entry != registry.end()) {
                wipe(entry->second.fingerprint);
            }
            entry =
                registry
                    .insert_or_assign(key, UsmHolder{.fingerprint = m_fingerprint, .holders = 0})
                    .first;
        }

        m_engineId = std::move(engineId);
        std::string error;
        m_channel = openChannel(error);
        if (!m_channel) {
            if (entry->second.holders == 0) {
                forgetUsmUser(key);
                wipe(entry->second.fingerprint);
                registry.erase(entry);
            }
            m_engineId.clear();
            m_state = State::idle;
            failAll(Error{.code = TransportError::sendFailed,
                          .message = "cannot open session: " + error});
            return;
        }
        ++entry->second.holders;
        m_usmKey = std::move(key);
        m_state = State::ready;

        std::vector<std::uint64_t> queued;
        for (const auto& [id, pending] : m_pending) {
            if (!pending.sent) {
                queued.push_back(id);
            }
        }
        for (const auto id : queued) {
            send(id);
        }
    }

    /// Opens the authenticated session for m_engineId with this Session's localized keys.
    std::shared_ptr<Channel> openChannel(std::string& error) {
        netsnmp_session config{};
        baseConfig(config);
        std::string user = m_identity.user;
        config.securityName = user.data();
        config.securityNameLen = user.size();
        config.securityLevel = toNetSnmp(m_identity.level);
        config.securityEngineID = m_engineId.data();
        config.securityEngineIDLen = m_engineId.size();
        if (m_identity.auth) {
            const ProtocolOid protocol = toNetSnmp(*m_identity.auth);
            config.securityAuthProto = protocol.oid;
            config.securityAuthProtoLen = protocol.length;
            std::memcpy(config.securityAuthKey, m_authKey.data(), m_authKeyLength);
            config.securityAuthKeyLen = m_authKeyLength;
        }
        if (m_identity.priv) {
            const ProtocolOid protocol = toNetSnmp(*m_identity.priv);
            config.securityPrivProto = protocol.oid;
            config.securityPrivProtoLen = protocol.length;
            std::memcpy(config.securityPrivKey, m_privKey.data(), m_privKeyLength);
            config.securityPrivKeyLen = m_privKeyLength;
        }

        std::shared_ptr<Channel> channel;
        try {
            channel = Channel::open(m_executor, config, weak_from_this(), error);
        } catch (...) {
            explicit_bzero(static_cast<void*>(config.securityAuthKey),
                           sizeof config.securityAuthKey);
            explicit_bzero(static_cast<void*>(config.securityPrivKey),
                           sizeof config.securityPrivKey);
            throw;
        }
        explicit_bzero(static_cast<void*>(config.securityAuthKey), sizeof config.securityAuthKey);
        explicit_bzero(static_cast<void*>(config.securityPrivKey), sizeof config.securityPrivKey);
        return channel;
    }

    void send(std::uint64_t id) {
        auto it = m_pending.find(id);
        if (it == m_pending.end()) {
            return;
        }
        if (!m_channel) {
            // Closed by reconcileChannel to drop abandoned requests; reopen on demand.
            std::string error;
            m_channel = openChannel(error);
            if (!m_channel) {
                complete(id, Error{.code = TransportError::sendFailed,
                                   .message = "cannot reopen session: " + error});
                return;
            }
        }
        Pending& pending = it->second;
        int command = SNMP_MSG_GET;
        switch (pending.kind) {
        case RequestKind::get: command = SNMP_MSG_GET; break;
        case RequestKind::getNext: command = SNMP_MSG_GETNEXT; break;
        case RequestKind::getBulk: command = SNMP_MSG_GETBULK; break;
        case RequestKind::set: command = SNMP_MSG_SET; break;
        }
        netsnmp_pdu* pdu = snmp_pdu_create(command);
        if (pending.kind == RequestKind::getBulk) {
            pdu->non_repeaters = 0;
            pdu->max_repetitions = static_cast<long>(m_options.maxRepetitions);
        }
        for (std::size_t i = 0; i < pending.varbinds.size(); ++i) {
            if (!addVariable(*pdu, pending.varbinds[i])) {
                snmp_free_pdu(pdu);
                complete(id, Error{.code = TransportError::sendFailed,
                                   .index = static_cast<std::uint32_t>(i + 1),
                                   .message = "net-snmp could not encode the varbind"});
                return;
            }
        }
        void* magic = reinterpret_cast<void*>(static_cast<std::uintptr_t>(id));
        if (snmp_sess_async_send(m_channel->handle(), pdu, &requestCallback, magic) == 0) {
            std::string error = sessionError(m_channel->handle());
            snmp_free_pdu(pdu);
            complete(id, Error{.code = TransportError::sendFailed, .message = std::move(error)});
            return;
        }
        pending.sent = true;
        ++m_sent;
        pending.varbinds.clear();
    }

    /// Completes a cancelled operation. net-snmp has no way to dequeue a single request, so one
    /// already sent is remembered until net-snmp drops it or reconcileChannel closes the channel.
    void abandon(std::uint64_t id) {
        auto it = m_pending.find(id);
        if (it == m_pending.end()) {
            return;
        }
        if (it->second.sent) {
            m_abandoned.insert(id);
        }
        complete(id, Error{.code = TransportError::aborted, .message = "operation cancelled"});
    }

    /// Never calls into net-snmp, so it is safe inside net-snmp callbacks.
    void complete(std::uint64_t id, Result<Varbinds> result) {
        auto it = m_pending.find(id);
        if (it == m_pending.end()) {
            return;
        }
        VarbindsHandler handler = std::move(it->second.handler);
        if (it->second.sent) {
            --m_sent;
        }
        m_pending.erase(it);
        if (auto slot = asio::get_associated_cancellation_slot(handler); slot.is_connected()) {
            slot.clear();
        }
        postCompletion(std::move(handler), std::move(result));
    }

    void postCompletion(VarbindsHandler handler, Result<Varbinds> result) {
        // Deferred, never inline: completions must not run inside net-snmp's call stack.
        asio::post(m_executor, asio::append(std::move(handler), std::move(result)));
    }

    void failAll(const Error& error) {
        std::vector<std::uint64_t> ids;
        ids.reserve(m_pending.size());
        for (const auto& entry : m_pending) {
            ids.push_back(entry.first);
        }
        for (const auto id : ids) {
            complete(id, error);
        }
    }

    /// Outside net-snmp frames only.
    void updateActivity() {
        reconcileChannel();
        if (m_probe) {
            m_probe->setActive(m_state == State::discovering);
        }
        if (m_channel) {
            m_channel->setActive(m_sent > 0 || !m_abandoned.empty());
        }
    }

    /// Once no live operation is queued in net-snmp, closes the channel if it still holds
    /// abandoned requests (closing is the only way to stop net-snmp retransmitting them) or if
    /// the engineID needs verifying (after a timeout or an unknownEngineID Report), in which case
    /// discovery runs again for the operations queued meanwhile. Operations in flight are never
    /// failed to make this happen.
    void reconcileChannel() {
        if (m_state != State::ready || m_sent > 0) {
            return;
        }
        if (m_channel && (m_rediscover || !m_abandoned.empty())) {
            m_channel->close(); // net-snmp reports each abandoned request as timed out
            m_channel.reset();
            m_abandoned.clear();
        }
        if (m_rediscover) {
            m_rediscover = false;
            releaseUsm();
            m_engineId.clear();
            m_state = State::idle;
            if (!m_pending.empty()) { // all unsent: m_sent == 0
                startDiscovery();
            }
        }
    }

    void closeChannels() noexcept {
        if (m_probe) {
            m_probe->close();
            m_probe.reset();
        }
        if (m_channel) {
            m_channel->close();
            m_channel.reset();
        }
    }

    void releaseUsm() noexcept {
        if (!m_usmKey) {
            return;
        }
        auto& registry = usmRegistry();
        if (auto entry = registry.find(*m_usmKey);
            entry != registry.end() && --entry->second.holders == 0) {
            forgetUsmUser(entry->first); // do not leave keys in net-snmp's table
            wipe(entry->second.fingerprint);
            registry.erase(entry);
        }
        m_usmKey.reset();
    }

    /// What the Session keeps of its Credentials: everything except the passphrases.
    struct Identity {
        std::string user;
        SecurityLevel level;
        std::optional<AuthProtocol> auth;
        std::optional<PrivProtocol> priv;
    };

    Executor m_executor;
    std::string m_peername;
    Identity m_identity;
    Options m_options;

    std::array<u_char, USM_AUTH_KU_LEN> m_authKey{};
    std::size_t m_authKeyLength{0};
    std::array<u_char, USM_PRIV_KU_LEN> m_privKey{};
    std::size_t m_privKeyLength{0};
    std::vector<u_char> m_fingerprint;

    State m_state{State::idle};
    std::shared_ptr<Channel> m_probe;
    std::shared_ptr<Channel> m_channel;
    std::optional<std::variant<std::vector<u_char>, Error>> m_probeOutcome;
    std::optional<UsmKey> m_usmKey;
    std::vector<u_char> m_engineId;
    bool m_rediscover{false};
    std::map<std::uint64_t, Pending> m_pending;
    std::size_t m_sent{0};               ///< m_pending entries queued in net-snmp
    std::set<std::uint64_t> m_abandoned; ///< cancelled after sending; still queued in net-snmp
    std::uint64_t m_nextId{1};
};

namespace {

void Channel::notifyOwner() {
    if (auto owner = m_owner.lock()) {
        owner->onChannelActivity(*this);
    }
}

int requestCallback(int operation, netsnmp_session* session, int /*requestId*/, netsnmp_pdu* pdu,
                    void* magic) noexcept {
    // The per-request magic is our id: net-snmp passes requestId 0 for Reports to unauthenticated
    // requests, so the request id cannot be used to find the operation.
    // Mirrors net-snmp's own test for the notInTimeWindow resend.
    ReportAction report = ReportAction::none;
    if (operation == NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE && pdu != nullptr &&
        pdu->command == SNMP_MSG_REPORT) {
        const int type = snmpv3_get_report_type(pdu);
        if (session->s_snmp_errno == SNMPERR_NOT_IN_TIME_WINDOW ||
            type == SNMPERR_NOT_IN_TIME_WINDOW) {
            report = ReportAction::resend;
        } else if (type == SNMPERR_UNKNOWN_ENG_ID) {
            report = ReportAction::engineChanged;
        }
    }
    auto* impl = static_cast<SessionImpl*>(session->callback_magic);
    impl->onResponse(std::uint64_t{reinterpret_cast<std::uintptr_t>(magic)}, operation, pdu,
                     report);
    return 1;
}

int probeCallback(int operation, netsnmp_session* session, int /*requestId*/, netsnmp_pdu* pdu,
                  void* /*magic*/) noexcept {
    static_cast<SessionImpl*>(session->callback_magic)->onProbeResponse(operation, pdu);
    return 1;
}

Varbinds nullVarbinds(std::vector<Oid> oids) {
    Varbinds varbinds;
    varbinds.reserve(oids.size());
    for (auto& oid : oids) {
        varbinds.push_back(Varbind::null(std::move(oid)));
    }
    return varbinds;
}

/// Starts @p kind on the io_context thread, whatever thread initiated it.
void start(const std::shared_ptr<SessionImpl>& impl, RequestKind kind, Varbinds varbinds,
           VarbindsHandler handler) {
    asio::dispatch(impl->executor(), [impl, kind, varbinds = std::move(varbinds),
                                      handler = std::move(handler)]() mutable {
        impl->submit(kind, std::move(varbinds), std::move(handler));
    });
}

RequestKind toRequestKind(Command command) {
    switch (command) {
    case Command::get: return RequestKind::get;
    case Command::getNext: return RequestKind::getNext;
    case Command::getBulk: return RequestKind::getBulk;
    }
    throw std::invalid_argument("unknown Command");
}

} // namespace

// ---------------------------------------------------------------------------------------------
// Entry points from session.hpp
// ---------------------------------------------------------------------------------------------

void validateOids(const std::vector<Oid>& oids) {
    if (oids.empty()) {
        throw std::invalid_argument("request needs at least one OID");
    }
}

void initiateRead(const std::shared_ptr<SessionImpl>& impl, Command command, std::vector<Oid> oids,
                  VarbindsHandler handler) {
    start(impl, toRequestKind(command), nullVarbinds(std::move(oids)), std::move(handler));
}

void initiateSet(const std::shared_ptr<SessionImpl>& impl, std::vector<Varbind> varbinds,
                 VarbindsHandler handler) {
    start(impl, RequestKind::set, std::move(varbinds), std::move(handler));
}

/// Walk is a composed operation: a co_composed coroutine issuing getBulk until the subtree ends
/// (ADR 0007). It holds the SessionImpl weakly so an in-progress walk never keeps a destroyed
/// Session alive.
void initiateWalk(const std::shared_ptr<SessionImpl>& impl, Oid root, VarbindsHandler handler) {
    const auto executor = impl->executor();
    const std::size_t limit = impl->options().maxWalkVarbinds;
    asio::dispatch(executor, [weak = std::weak_ptr(impl), executor, limit, root = std::move(root),
                              handler = std::move(handler)]() mutable {
        asio::async_initiate<VarbindsHandler, VarbindsSignature>(
            asio::co_composed<VarbindsSignature>(
                [](auto state, std::weak_ptr<SessionImpl> session, Oid subtree,
                   SessionImpl::Executor ioExecutor, std::size_t maxVarbinds) -> void {
                    state.throw_if_cancelled(false);
                    state.reset_cancellation_state(asio::enable_terminal_cancellation());

                    Varbinds collected;
                    Oid cursor = subtree;
                    while (true) {
                        auto page = co_await asio::async_initiate<const asio::deferred_t&,
                                                                  VarbindsSignature>(
                            [&session, ioExecutor](VarbindsHandler pageHandler, Oid from) {
                                if (auto live = session.lock()) {
                                    live->submit(RequestKind::getBulk,
                                                 {Varbind::null(std::move(from))},
                                                 std::move(pageHandler));
                                } else {
                                    asio::post(ioExecutor,
                                               asio::append(std::move(pageHandler),
                                                            Result<Varbinds>(Error{
                                                                .code = TransportError::aborted,
                                                                .message = "session destroyed"})));
                                }
                            },
                            asio::deferred, cursor);
                        if (!page) {
                            co_return {std::move(page)};
                        }
                        bool finished = page->empty();
                        for (Varbind& varbind : *page) {
                            if (std::holds_alternative<NoSuch>(varbind.value) ||
                                !subtree.isPrefixOf(varbind.oid) || varbind.oid == subtree) {
                                finished = true;
                                break;
                            }
                            if (varbind.oid <= cursor) {
                                co_return {Result<Varbinds>(
                                    Error{.code = PduError::genErr,
                                          .message = "agent returned non-increasing OID " +
                                                     varbind.oid.toString() + " after " +
                                                     cursor.toString()})};
                            }
                            if (collected.size() == maxVarbinds) {
                                // A misbehaving agent must not grow memory without bound.
                                co_return {Result<Varbinds>(
                                    Error{.code = TransportError::limitExceeded,
                                          .message = "walk returned more than " +
                                                     std::to_string(maxVarbinds) +
                                                     " varbinds (Options::maxWalkVarbinds)"})};
                            }
                            cursor = varbind.oid;
                            collected.push_back(std::move(varbind));
                        }
                        if (finished) {
                            break;
                        }
                    }
                    co_return {Result<Varbinds>(std::move(collected))};
                },
                executor),
            handler, std::move(weak), std::move(root), executor, limit);
    });
}

} // namespace snmp_coro::detail

// NOLINTEND(cppcoreguidelines-pro-type-union-access,cppcoreguidelines-pro-bounds-pointer-arithmetic,cppcoreguidelines-pro-type-reinterpret-cast,cppcoreguidelines-avoid-c-arrays,modernize-avoid-c-arrays,cppcoreguidelines-pro-type-const-cast,cppcoreguidelines-no-malloc,cppcoreguidelines-owning-memory,cppcoreguidelines-pro-bounds-array-to-pointer-decay,performance-no-int-to-ptr)

// ---------------------------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------------------------

namespace snmp_coro {

Session::Session(boost::asio::io_context& context, const boost::asio::ip::udp::endpoint& target,
                 const Credentials& credentials, Options options)
    : m_executor(context.get_executor()),
      m_impl(std::make_shared<detail::SessionImpl>(m_executor, target, credentials, options)) {}

namespace {

/// Shuts @p impl down on its io_context thread: inline when already there (or when nothing runs
/// the io_context any more), otherwise posted.
void shutdownImpl(const Session::executor_type& executor,
                  std::shared_ptr<detail::SessionImpl> impl) noexcept {
    if (!impl) {
        return;
    }
    try {
        if (executor.running_in_this_thread() || executor.context().stopped()) {
            impl->shutdown();
            return;
        }
        boost::asio::post(executor, [impl = std::move(impl)] { impl->shutdown(); });
    } catch (...) { // NOLINT(bugprone-empty-catch)
        // Out of memory while posting: ~SessionImpl still releases net-snmp resources once the
        // last reference goes; pending handlers are then destroyed without being invoked.
    }
}

} // namespace

Session::~Session() {
    shutdownImpl(m_executor, std::move(m_impl));
}

Session::Session(Session&& other) noexcept
    : m_executor(std::move(other.m_executor)), m_impl(std::move(other.m_impl)) {}

Session& Session::operator=(Session&& other) noexcept {
    if (this != &other) {
        shutdownImpl(m_executor, std::move(m_impl));
        m_executor = std::move(other.m_executor);
        m_impl = std::move(other.m_impl);
    }
    return *this;
}

Session::executor_type Session::get_executor() const noexcept {
    return m_executor;
}

const std::shared_ptr<detail::SessionImpl>& Session::impl() const {
    if (!m_impl) {
        throw std::logic_error("operation on a moved-from snmp_coro::Session");
    }
    return m_impl;
}

} // namespace snmp_coro
