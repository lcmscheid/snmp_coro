// SPDX-License-Identifier: MIT
#include "agent.hpp"

#include <catch2/catch_test_macros.hpp>

#include <boost/asio/ip/address.hpp>

#include <chrono>
#include <csignal>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <memory>
#include <sstream>
#include <thread>

#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

extern char**
    environ; // NOLINT(readability-redundant-declaration,cppcoreguidelines-avoid-non-const-global-variables)

namespace test {

using namespace snmp_coro;
using boost::asio::ip::udp;

namespace {

std::filesystem::path makeTempDirectory() {
    std::string pattern =
        (std::filesystem::temp_directory_path() / "snmp_coro_agent_XXXXXX").string();
    if (::mkdtemp(pattern.data()) == nullptr) {
        throw std::runtime_error("mkdtemp failed");
    }
    return {pattern};
}

unsigned short freeUdpPort() {
    boost::asio::io_context context;
    const udp::socket socket(context, udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0));
    return socket.local_endpoint().port();
}

} // namespace

Agent& Agent::instance() {
    static std::unique_ptr<Agent> agent;
    static std::string failure;
    if (!agent && failure.empty()) {
        auto candidate = std::unique_ptr<Agent>(new Agent());
        if (candidate->start(failure)) {
            agent = std::move(candidate);
        }
    }
    if (!agent) {
        SKIP("snmpd unavailable: " << failure);
    }
    return *agent;
}

std::unique_ptr<Agent> Agent::spawn(const std::string& engineId, unsigned short port) {
    auto agent = std::unique_ptr<Agent>(new Agent());
    agent->m_engineId = engineId;
    if (port != 0) {
        agent->m_endpoint = udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), port);
    }
    std::string why;
    if (!agent->start(why)) {
        SKIP("snmpd unavailable: " << why);
    }
    return agent;
}

void Agent::restart() {
    stop();
    std::string why;
    if (!start(why)) {
        SKIP("snmpd did not restart: " << why);
    }
}

void Agent::stop() {
    if (m_pid > 0) {
        ::kill(m_pid, SIGTERM);
        int status = 0;
        ::waitpid(m_pid, &status, 0);
        m_pid = -1;
    }
}

bool Agent::start(std::string& why) {
    const std::string snmpd = SNMP_CORO_SNMPD;
    if (snmpd.empty()) {
        why = "snmpd was not found at configure time";
        return false;
    }
    if (m_directory.empty()) {
        m_directory = makeTempDirectory();
    }
    if (m_endpoint.port() == 0) {
        m_endpoint = udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), freeUdpPort());
    }

    const auto persist = m_directory / "persist";
    std::filesystem::create_directories(persist);
    const auto config = m_directory / "snmpd.conf";
    {
        std::ofstream out(config);
        out << "agentAddress udp:127.0.0.1:" << m_endpoint.port() << '\n'
            << "[snmp] persistentDir " << persist.string() << '\n';
        ++m_starts;
        if (!m_engineId.empty()) {
            // With -C snmpd ignores the state it persisted, which would reset engineBoots to 1 on
            // every start; state it here. snmpd keeps engineBoots only while oldEngineID matches
            // the engineID, which for a text engineID is 80 00 1F 88 04 followed by the text.
            std::ostringstream oldEngineId;
            oldEngineId << "0x80001f8804" << std::hex << std::setfill('0');
            for (const char c : m_engineId) {
                oldEngineId << std::setw(2) << static_cast<unsigned>(static_cast<unsigned char>(c));
            }
            out << "engineID " << m_engineId << '\n'
                << "oldEngineID " << oldEngineId.str() << '\n'
                << "engineBoots " << m_starts << '\n';
        }
        out << "createUser noauthuser\n"
            << "createUser md5only MD5 \"" << authPass << "\"\n"
            << "createUser md5des MD5 \"" << authPass << "\" DES \"" << privPass << "\"\n"
            << "createUser shaaes SHA \"" << authPass << "\" AES \"" << privPass << "\"\n"
            << "createUser sha256aes SHA-256 \"" << authPass << "\" AES \"" << privPass << "\"\n"
            << "createUser sha512aes SHA-512 \"" << authPass << "\" AES \"" << privPass
            << "\"\n"
            // rouser/rwuser default to requiring auth; noauth must be explicit (ADR 0004).
            << "rouser noauthuser noauth\n"
            << "rouser md5only auth\n"
            << "rwuser md5des priv\n"
            << "rwuser shaaes priv\n"
            << "rwuser sha256aes priv\n"
            << "rwuser sha512aes priv\n";
    }

    const std::string persistEnv = "SNMP_PERSISTENT_DIR=" + persist.string();
    std::vector<char*> environment;
    for (char* const* e = environ; *e != nullptr;
         ++e) { // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        environment.push_back(*e);
    }
    environment.push_back(
        const_cast<char*>(persistEnv.c_str())); // NOLINT(cppcoreguidelines-pro-type-const-cast)
    environment.push_back(nullptr);

    const std::string configArg = config.string();
    const std::string logArg = (m_directory / "snmpd.log").string();
    std::vector<std::string> args{snmpd, "-f", "-C", "-c", configArg, "-Lf", logArg};
    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    for (auto& arg : args) {
        argv.push_back(arg.data());
    }
    argv.push_back(nullptr);

    pid_t pid = 0;
    if (::posix_spawn(&pid, snmpd.c_str(), nullptr, nullptr, argv.data(), environment.data()) !=
        0) {
        why = "posix_spawn(" + snmpd + ") failed";
        return false;
    }
    m_pid = pid;

    // Ready when an unauthenticated get succeeds.
    for (int attempt = 0; attempt < 50; ++attempt) {
        int status = 0;
        if (::waitpid(m_pid, &status, WNOHANG) == m_pid) {
            m_pid = -1;
            why = "snmpd exited during start-up; see " + logArg;
            return false;
        }
        boost::asio::io_context context;
        Session probe(context, m_endpoint, Credentials::noAuthNoPriv("noauthuser"),
                      Options{.timeout = std::chrono::milliseconds(100), .retries = 0});
        const auto result = wait(context, [&](auto handler) { probe.get({sysDescr}, handler); });
        if (result.has_value()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    why = "snmpd did not answer within 5 s; see " + logArg;
    return false;
}

Agent::~Agent() {
    stop();
    std::error_code ignored;
    std::filesystem::remove_all(m_directory, ignored);
}

std::vector<NamedCredentials> allUsers() {
    return {
        {.name = "noAuthNoPriv",
         .credentials = Credentials::noAuthNoPriv("noauthuser"),
         .writable = false},
        {.name = "authNoPriv MD5",
         .credentials = Credentials::authNoPriv("md5only", AuthProtocol::md5, authPass),
         .writable = false},
        {.name = "authPriv MD5+DES",
         .credentials = Credentials::authPriv("md5des", AuthProtocol::md5, authPass,
                                              PrivProtocol::des, privPass),
         .writable = true},
        {.name = "authPriv SHA1+AES",
         .credentials = Credentials::authPriv("shaaes", AuthProtocol::sha1, authPass,
                                              PrivProtocol::aes128, privPass),
         .writable = true},
        {.name = "authPriv SHA256+AES",
         .credentials = Credentials::authPriv("sha256aes", AuthProtocol::sha256, authPass,
                                              PrivProtocol::aes128, privPass),
         .writable = true},
        {.name = "authPriv SHA512+AES",
         .credentials = Credentials::authPriv("sha512aes", AuthProtocol::sha512, authPass,
                                              PrivProtocol::aes128, privPass),
         .writable = true},
    };
}

Credentials readWriteUser() {
    return Credentials::authPriv("sha256aes", AuthProtocol::sha256, authPass, PrivProtocol::aes128,
                                 privPass);
}

udp::endpoint deadEndpoint() {
    return {boost::asio::ip::make_address("127.0.0.1"), freeUdpPort()};
}

Options fastOptions() {
    return Options{.timeout = std::chrono::milliseconds(300), .retries = 1};
}

Session makeSession(boost::asio::io_context& context, const Credentials& credentials,
                    Options options) {
    return {context, Agent::instance().endpoint(), credentials, options};
}

} // namespace test
