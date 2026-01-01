// main.cpp - Server entry point for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#include <asio.hpp>
#include <iostream>
#include <thread>
#include <chrono>
#include <columnlynx/common/utils.hpp>
#include <columnlynx/common/panic_handler.hpp>
#include <columnlynx/server/net/tcp/tcp_server.hpp>
#include <columnlynx/server/net/udp/udp_server.hpp>
#include <columnlynx/common/libsodium_wrapper.hpp>
#include <unordered_set>
#include <unordered_map>
#include <cxxopts.hpp>
#include <columnlynx/common/net/virtual_interface.hpp>

#if defined(__WIN32__)
#include <windows.h>
#endif

using asio::ip::tcp;
using namespace ColumnLynx::Utils;
using namespace ColumnLynx::Net::TCP;
using namespace ColumnLynx::Net::UDP;
using namespace ColumnLynx::Net;
using namespace ColumnLynx;

volatile sig_atomic_t done = 0;

int main(int argc, char** argv) {

    cxxopts::Options options("columnlynx_server", "ColumnLynx Server Application");

    options.add_options()
        ("h,help", "Print help")
        ("4,ipv4-only", "Force IPv4 only operation", cxxopts::value<bool>()->default_value("false"))
#if defined(__APPLE__)
        ("i,interface", "Override used interface", cxxopts::value<std::string>()->default_value("utun0"))
#else
        ("i,interface", "Override used interface", cxxopts::value<std::string>()->default_value("lynx0"))
#endif
#if defined(__WIN32__)
/* Get config dir in LOCALAPPDATA\ColumnLynx\ */
        ("config-dir", "Override config dir path", cxxopts::value<std::string>()->default_value("C:\\ProgramData\\ColumnLynx\\"));
#else
        ("config-dir", "Override config dir path", cxxopts::value<std::string>()->default_value("/etc/columnlynx"));
#endif

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
        //WintunInitialize();
#endif

        // Get the config path, ENV > CLI > /etc/columnlynx
        std::string configPath = optionsObj["config-dir"].as<std::string>();
        const char* envConfigPath = std::getenv("COLUMNLYNX_CONFIG_DIR");
        if (envConfigPath != nullptr) {
            configPath = std::string(envConfigPath);
        }

        if (configPath.back() != '/' && configPath.back() != '\\') {
            #if defined(__WIN32__)
            configPath += "\\";
            #else
            configPath += "/";
            #endif
        }

        std::unordered_map<std::string, std::string> config = Utils::getConfigMap(configPath + "server_config");

        std::shared_ptr<VirtualInterface> tun = std::make_shared<VirtualInterface>(optionsObj["interface"].as<std::string>());
        log("Using virtual interface: " + tun->getName());

        // Generate a temporary keypair, replace with actual CA signed keys later (Note, these are stored in memory)
        std::shared_ptr<LibSodiumWrapper> sodiumWrapper = std::make_shared<LibSodiumWrapper>();

        auto itPubkey = config.find("SERVER_PUBLIC_KEY");
        auto itPrivkey = config.find("SERVER_PRIVATE_KEY");

        if (itPubkey != config.end() && itPrivkey != config.end()) {
            log("Loading keypair from config file.");

            PublicKey pk;
            PrivateSeed seed;

            std::copy_n(Utils::hexStringToBytes(itPrivkey->second).begin(), seed.size(), seed.begin());
            std::copy_n(Utils::hexStringToBytes(itPubkey->second).begin(), pk.size(), pk.begin());

            if (!sodiumWrapper->recomputeKeys(seed, pk)) {
                throw std::runtime_error("Failed to recompute keypair from config file values!");
            }
        } else {
            #if defined(DEBUG)
            warn("No keypair found in config file! Using random key.");
            #else
            throw std::runtime_error("No keypair found in config file! Cannot start server without keys.");
            #endif
        }

        log("Server public key: " + bytesToHexString(sodiumWrapper->getPublicKey(), crypto_sign_PUBLICKEYBYTES));

        std::shared_ptr<bool> hostRunning = std::make_shared<bool>(true);

        asio::io_context io;

        auto server = std::make_shared<TCPServer>(io, serverPort(), sodiumWrapper, hostRunning, configPath, ipv4Only);
        auto udpServer = std::make_shared<UDPServer>(io, serverPort(), hostRunning, ipv4Only, tun);

        asio::signal_set signals(io, SIGINT, SIGTERM);
        signals.async_wait([&](const std::error_code&, int) {
            log("Received termination signal. Shutting down server gracefully.");
            done = 1;
            asio::post(io, [&]() {
                *hostRunning = false;
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
                // Small sleep to avoid busy-waiting and to allow signal processing
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }

            const uint8_t* ip = packet.data();
            uint32_t srcIP = ntohl(*(uint32_t*)(ip + 12)); // IPv4 source address offset
            uint32_t dstIP = ntohl(*(uint32_t*)(ip + 16)); // IPv4 destination address offset
        
            // First, check if destination IP is a registered client (e.g., server responding to client or client-to-client)
            auto dstSession = SessionRegistry::getInstance().getByIP(dstIP);
            if (dstSession) {
                // Destination is a registered client, forward to that client's session
                udpServer->sendData(dstSession->sessionID, std::string(packet.begin(), packet.end()));
                continue;
            }

            // Destination is not a registered client, check if source is (for external routing)
            auto srcSession = SessionRegistry::getInstance().getByIP(srcIP);
            if (srcSession) {
                // Source is a registered client, write to TUN interface to forward to external destination
                tun->writePacket(packet);
                continue;
            }

            // Neither source nor destination is registered, drop the packet
            Utils::warn("TUN: No session found for source IP " + VirtualInterface::ipv4ToString(srcIP) + 
                       " or destination IP " + VirtualInterface::ipv4ToString(dstIP));
        }

        log("Shutting down server...");

        io.stop();
        if (ioThread.joinable()) {
            ioThread.join();
        }

        log("Server stopped.");
    } catch (const std::exception& e) {
        error("Server error: " + std::string(e.what()));
    }
}