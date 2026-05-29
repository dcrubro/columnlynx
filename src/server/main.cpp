// main.cpp - Server entry point for ColumnLynx
// Copyright (C) 2026 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#include <asio.hpp>
#include <iostream>
#include <thread>
#include <chrono>
#include <filesystem>
#include <cstring>
#include <columnlynx/common/utils.hpp>
#include <columnlynx/common/panic_handler.hpp>
#include <columnlynx/server/net/tcp/tcp_server.hpp>
#include <columnlynx/server/net/udp/udp_server.hpp>
#include <columnlynx/common/libsodium_wrapper.hpp>
#include <unordered_set>
#include <unordered_map>
#include <cxxopts.hpp>
#include <columnlynx/common/net/virtual_interface.hpp>
#include <columnlynx/server/server_session.hpp>

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
            std::cout << "Copyright (C) 2026, The ColumnLynx Contributors.\n";
            std::cout << "This software is provided under ABSOLUTELY NO WARRANTY, to the extent permitted by law.\n";
            return 0;
        }

        bool ipv4Only = optionsObj["ipv4-only"].as<bool>();

        log("ColumnLynx Server, Version " + getVersion());
        log("This software is licensed under the GPLv2 only OR the GPLv3. See LICENSES/ for details.");

#if defined(__WIN32__)
        //WintunInitialize();
#endif

        struct ServerState serverState{};

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

        serverState.configPath = configPath;

#if defined(DEBUG)
    std::unordered_map<std::string, std::string> config = Utils::getConfigMap(configPath + "server_config", { "NETWORK", "SUBNET_MASK" });
#else
    std::unordered_map<std::string, std::string> config = Utils::getConfigMap(configPath + "server_config", { "NETWORK", "SUBNET_MASK" });
#endif

        serverState.serverConfig = config;

        std::shared_ptr<VirtualInterface> tun = std::make_shared<VirtualInterface>(optionsObj["interface"].as<std::string>());
        log("Using virtual interface: " + tun->getName());

        // Store a reference to the tun in the serverState, it will increment and keep a safe reference (we love shared_ptrs)
        serverState.virtualInterface = tun;

        std::shared_ptr<LibSodiumWrapper> sodiumWrapper = std::make_shared<LibSodiumWrapper>();

        const std::string serverPublicKeyPath = configPath + "public.key";
        const std::string serverPrivateKeyPath = configPath + "private.key";

        namespace fs = std::filesystem;
        bool serverKeyFilesPresent = fs::exists(serverPublicKeyPath) && fs::exists(serverPrivateKeyPath);
        if (serverKeyFilesPresent) {
            log("Loading server keypair from key files.");

            PublicKey pk = Utils::loadHexArrayFromFile<crypto_sign_PUBLICKEYBYTES>(serverPublicKeyPath, "server public key");
            PrivateSeed seed = Utils::loadHexArrayFromFile<crypto_sign_SEEDBYTES>(serverPrivateKeyPath, "server private key", true);

            if (!sodiumWrapper->recomputeKeys(seed, pk)) {
                throw std::runtime_error("Failed to recompute keypair from key files!");
            }
        } else {
#if defined(DEBUG)
            warn("No server keypair files found! Using random key.");
#else
            throw std::runtime_error("No server keypair files found! Cannot start server without keys.");
#endif
        }

        log("Server public key: " + bytesToHexString(sodiumWrapper->getPublicKey(), crypto_sign_PUBLICKEYBYTES));

        serverState.sodiumWrapper = sodiumWrapper;
        serverState.ipv4Only = ipv4Only;
        serverState.hostRunning = true;

        // Store the global state; from now on, it should only be accessed through the ServerSession singleton, which will ensure thread safety with its internal mutex
        ServerSession::getInstance().setServerState(std::make_shared<ServerState>(std::move(serverState)));

        asio::io_context io;

        auto server = std::make_shared<TCPServer>(io, serverPort());
        auto udpServer = std::make_shared<UDPServer>(io, serverPort());

        // Schedule periodic cleanup of expired sessions every 5 minutes
        auto cleanupTimer = std::make_shared<asio::steady_timer>(io);
        auto cleanupHandler = std::make_shared<std::function<void(const asio::error_code&)>>();
        *cleanupHandler = [cleanupTimer, cleanupHandler](const asio::error_code& ec) {
            if (ec == asio::error::operation_aborted) return; // Timer cancelled
            try {
                SessionRegistry::getInstance().cleanupExpired();
            } catch (const std::exception& e) {
                Utils::warn(std::string("SessionRegistry::cleanupExpired() threw: ") + e.what());
            }
            cleanupTimer->expires_after(std::chrono::minutes(5));
            cleanupTimer->async_wait(*cleanupHandler);
        };
        cleanupTimer->expires_after(std::chrono::minutes(5));
        cleanupTimer->async_wait(*cleanupHandler);

        asio::signal_set signals(io, SIGINT, SIGTERM);
        signals.async_wait([&](const std::error_code&, int) {
            log("Received termination signal. Shutting down server gracefully.");
            done = 1;
            asio::post(io, [&]() {
                ServerSession::getInstance().setHostRunning(false);
                server->stop();
                udpServer->stop();
                // Cancel cleanup timer
                cleanupTimer->cancel();
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

            if (packet.size() < 20) {
                Utils::warn("TUN: Dropping packet smaller than IPv4 header (" + std::to_string(packet.size()) + " bytes)");
                continue;
            }

            const uint8_t* ip = packet.data();
            uint8_t ipVersion = (ip[0] >> 4);
            if (ipVersion != 4) {
                Utils::debug("TUN: Non-IPv4 packet received (version=" + std::to_string(ipVersion) + "), skipping server IPv4 routing path.");
                continue;
            }

            uint32_t srcIPNet = 0;
            uint32_t dstIPNet = 0;
            std::memcpy(&srcIPNet, ip + 12, sizeof(srcIPNet)); // IPv4 source address offset
            std::memcpy(&dstIPNet, ip + 16, sizeof(dstIPNet)); // IPv4 destination address offset
            uint32_t srcIP = ntohl(srcIPNet);
            uint32_t dstIP = ntohl(dstIPNet);
        
            // First, check if destination IP is a registered client (e.g., server responding to client or client-to-client)
            auto dstSession = SessionRegistry::getInstance().getByIP(dstIP);
            if (dstSession) {
                // Destination is a registered client, enforce MTU and forward to that client's session
                const size_t MTU = 1420; // Enforce configured MTU; TODO: read from server config
                if (packet.size() > MTU) {
                    Utils::warn("TUN: Dropping oversized packet (" + std::to_string(packet.size()) + " > MTU " + std::to_string(MTU) + ")");
                } else {
                    udpServer->sendData(dstSession->sessionID, std::string(packet.begin(), packet.end()));
                }
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