// SPDX-License-Identifier: MIT
//
// Usage: snmp_coro_walk <host> <port> <user> <auth-pass> <priv-pass> [root-oid]
// Walks a subtree over SNMPv3 authPriv (SHA-256 + AES-128) and prints every varbind.
#include <snmp_coro/snmp_coro.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>

#include <cstdlib>
#include <exception>
#include <iostream>
#include <span>
#include <string>
#include <variant>

namespace asio = boost::asio;
using namespace snmp_coro;

namespace {

void print(const Varbind& varbind) {
    std::cout << varbind.oid.toString() << " = " << toString(varbind.type) << ": ";
    std::visit(
        [](const auto& value) {
            using T = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<T, std::monostate>) {
                std::cout << "null";
            } else if constexpr (std::is_same_v<T, Oid>) {
                std::cout << value.toString();
            } else if constexpr (std::is_same_v<T, NoSuch>) {
                std::cout << toString(value.value);
            } else {
                std::cout << value;
            }
        },
        varbind.value);
    std::cout << '\n';
}

asio::awaitable<void> run(Session& session, Oid root) {
    // The default completion token is asio::deferred, so operations can be co_awaited directly.
    const auto result = co_await session.walk(std::move(root));
    if (!result) {
        std::cerr << "walk failed: " << SnmpError(result.error()).what() << '\n';
        co_return;
    }
    for (const auto& varbind : *result) {
        print(varbind);
    }
}

} // namespace

int main(int argc, char** argv) {
    const std::span args(argv, static_cast<std::size_t>(argc));
    if (args.size() < 6) {
        std::cerr << "usage: " << args[0]
                  << " <host> <port> <user> <auth-pass> <priv-pass> [root-oid]\n";
        return EXIT_FAILURE;
    }
    try {
        asio::io_context context;
        const asio::ip::udp::endpoint target(asio::ip::make_address(args[1]),
                                             static_cast<unsigned short>(std::stoul(args[2])));
        Session session(context, target,
                        Credentials::authPriv(args[3], AuthProtocol::sha256, args[4],
                                              PrivProtocol::aes128, args[5]));
        const Oid root(args.size() > 6 ? args[6] : "1.3.6.1.2.1.1");
        asio::co_spawn(context, run(session, root), asio::detached);
        context.run();
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
