// main.cpp - Server entry point for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#include <asio.hpp>
#include <iostream>
#include <columnlynx/common/utils.hpp>
#include <columnlynx/common/panic_handler.hpp>
#include <columnlynx/server/net/tcp/tcp_server.hpp>
#include <columnlynx/server/net/udp/udp_server.hpp>
#include <columnlynx/common/libsodium_wrapper.hpp>
#include <unordered_set>
#include <unordered_map>
#include <cxxopts.hpp>
#include <columnlynx/common/net/virtual_interface.hpp>

using asio::ip::tcp;
using namespace ColumnLynx::Utils;
using namespace ColumnLynx::Net::TCP;
using namespace ColumnLynx::Net::UDP;
using namespace ColumnLynx::Net;
using namespace ColumnLynx;

volatile sig_atomic_t done = 0;

void signalHandler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        log("Received termination signal. Shutting down server gracefully.");
        done = 1;
    }
}

int main(int argc, char** argv) {
    // Capture SIGINT and SIGTERM for graceful shutdown
    struct sigaction action;
    memset(&action, 0, sizeof(struct sigaction));
    action.sa_handler = signalHandler;
    sigaction(SIGINT, &action, nullptr);
    sigaction(SIGTERM, &action, nullptr);

    cxxopts::Options options("columnlynx_server", "ColumnLynx Server Application");

    options.add_options()
        ("h,help", "Print help")
        ("4,ipv4-only", "Force IPv4 only operation", cxxopts::value<bool>()->default_value("false"))
#if defined(__APPLE__)
        ("i,interface", "Override used interface", cxxopts::value<std::string>()->default_value("utun0"))
#else
        ("i,interface", "Override used interface", cxxopts::value<std::string>()->default_value("lynx0"))
#endif
        ("config", "Override config file path", cxxopts::value<std::string>()->default_value("./server_config"));

    PanicHandler::init();

    try {
        auto optionsObj = options.parse(argc, argv);
        if (optionsObj.count("help")) {
            std::cout << options.help() << std::endl;
            std::cout << "This software is licensed under the GPLv2-only license OR the GPLv3 license.\n";
            std::cout << "Copyright (C) 2025, The ColumnLynx Contributors.\n";
            std::cout << "This software is provided under ABSOLUTELY NO WARRANTY, to the extent permitted by law.\n";
            return 0;
        }

        bool ipv4Only = optionsObj["ipv4-only"].as<bool>();

        log("ColumnLynx Server, Version " + getVersion());
        log("This software is licensed under the GPLv2 only OR the GPLv3. See LICENSES/ for details.");

#if defined(__WIN32__)
        WintunInitialize();
#endif

        std::unordered_map<std::string, std::string> config = Utils::getConfigMap(optionsObj["config"].as<std::string>());

        std::shared_ptr<VirtualInterface> tun = std::make_shared<VirtualInterface>(optionsObj["interface"].as<std::string>());
        log("Using virtual interface: " + tun->getName());

        // Generate a temporary keypair, replace with actual CA signed keys later (Note, these are stored in memory)
        LibSodiumWrapper sodiumWrapper = LibSodiumWrapper();

        auto itPubkey = config.find("SERVER_PUBLIC_KEY");
        auto itPrivkey = config.find("SERVER_PRIVATE_KEY");

        if (itPubkey != config.end() && itPrivkey != config.end()) {
            log("Loading keypair from config file.");

            PublicKey pk;
            PrivateKey sk;

            std::copy_n(Utils::hexStringToBytes(itPrivkey->second).begin(), sk.size(), sk.begin());
            std::copy_n(Utils::hexStringToBytes(itPubkey->second).begin(), pk.size(), pk.begin());

            sodiumWrapper.setKeys(pk, sk);
        } else {
            warn("No keypair found in config file! Using random key.");
        }

        log("Server public key: " + bytesToHexString(sodiumWrapper.getPublicKey(), crypto_sign_PUBLICKEYBYTES));
        //log("Server private key: " + bytesToHexString(sodiumWrapper.getPrivateKey(), crypto_sign_SECRETKEYBYTES)); // TEMP, remove later

        bool hostRunning = true;

        asio::io_context io;

        auto server = std::make_shared<TCPServer>(io, serverPort(), &sodiumWrapper, &hostRunning, ipv4Only);
        auto udpServer = std::make_shared<UDPServer>(io, serverPort(), &hostRunning, ipv4Only, tun);

        asio::signal_set signals(io, SIGINT, SIGTERM);
        signals.async_wait([&](const std::error_code&, int) {
            log("Received termination signal. Shutting down server gracefully.");
            done = 1;
            asio::post(io, [&]() {
                hostRunning = false;
                server->stop();
                udpServer->stop();
            });
        });

        // Run the IO context in a separate thread
        std::thread ioThread([&io]() {
            io.run();
        });

        //ioThread.detach();

        log("Server started on port " + std::to_string(serverPort()));
        
        while (!done) {
            auto packet = tun->readPacket();
            if (packet.empty()) {
                continue;
            }

            const uint8_t* ip = packet.data();
            uint32_t dstIP = ntohl(*(uint32_t*)(ip + 16)); // IPv4 destination address offset in IPv6-mapped header
        
            auto session = SessionRegistry::getInstance().getByIP(dstIP);
            if (!session) {
                Utils::warn("TUN: No session found for destination IP " + VirtualInterface::ipv4ToString(dstIP));
                continue;
            }

            udpServer->sendData(session->sessionID, std::string(packet.begin(), packet.end()));
        }

        log("Shutting down server...");
        /*hostRunning = false;
        server->stop();
        udpServer->stop();*/

        io.stop();
        if (ioThread.joinable()) {
            ioThread.join();
        }

        log("Server stopped.");
    } catch (const std::exception& e) {
        error("Server error: " + std::string(e.what()));
    }
}