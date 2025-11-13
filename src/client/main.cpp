// main.cpp - Client entry point for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#include <asio/asio.hpp>
#include <csignal>
#include <iostream>
#include <columnlynx/common/utils.hpp>
#include <columnlynx/common/panic_handler.hpp>
#include <columnlynx/client/net/tcp/tcp_client.hpp>
#include <columnlynx/client/net/udp/udp_client.hpp>
#include <cxxopts/cxxopts.hpp>
#include <columnlynx/common/net/virtual_interface.hpp>

using asio::ip::tcp;
using namespace ColumnLynx::Utils;
using namespace ColumnLynx::Net;
using namespace ColumnLynx;

volatile sig_atomic_t done = 0;

void signalHandler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        //log("Received termination signal. Shutting down client.");
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

    PanicHandler::init();

    cxxopts::Options options("columnlynx_client", "ColumnLynx Client Application");

    options.add_options()
        ("h,help", "Print help")
        ("s,server", "Server address", cxxopts::value<std::string>()->default_value("127.0.0.1"))
        ("p,port", "Server port", cxxopts::value<uint16_t>()->default_value(std::to_string(serverPort())))
        ("allow-selfsigned", "Allow self-signed certificates", cxxopts::value<bool>()->default_value("false"));

    bool insecureMode = options.parse(argc, argv).count("allow-selfsigned") > 0;
    
    auto result = options.parse(argc, argv);
    if (result.count("help")) {
        std::cout << options.help() << std::endl;
        return 0;
    }

    auto host = result["server"].as<std::string>();
    auto port = std::to_string(result["port"].as<uint16_t>());

    try {
        log("ColumnLynx Client, Version " + getVersion());
        log("This software is licensed under the GPLv2 only OR the GPLv3. See LICENSES/ for details.");

#if defined(__WIN32__)
        WintunInitialize();
#endif

        std::shared_ptr<VirtualInterface> tun = std::make_shared<VirtualInterface>("utun1");
        log("Using virtual interface: " + tun->getName());

        LibSodiumWrapper sodiumWrapper = LibSodiumWrapper();

        std::array<uint8_t, 32> aesKey = {0}; // Defualt zeroed state until modified by handshake
        uint64_t sessionID = 0;

        asio::io_context io;
        auto client = std::make_shared<ColumnLynx::Net::TCP::TCPClient>(io, host, port, &sodiumWrapper, &aesKey, &sessionID, &insecureMode, tun);
        auto udpClient = std::make_shared<ColumnLynx::Net::UDP::UDPClient>(io, host, port, &aesKey, &sessionID, tun);

        client->start();
        udpClient->start();

        // Run the IO context in a separate thread
        std::thread ioThread([&io]() {
            io.run();
        });
        //ioThread.join();

        log("Client connected to " + host + ":" + port);
        
        // Client is running
        while ((client->isConnected() || !client->isHandshakeComplete()) && !done) {
            auto packet = tun->readPacket();
            if (!client->isConnected() || done) {
                break; // Bail out if connection died or signal set while blocked
            }
            
            if (packet.empty()) {
                continue;
            }
            
            udpClient->sendMessage(std::string(packet.begin(), packet.end()));
        }

        log("Client shutting down.");
        udpClient->stop();
        client->disconnect();
        io.stop();

        if (ioThread.joinable())
            ioThread.join();

    } catch (const std::exception& e) {
        error("Client error: " + std::string(e.what()));
    }
}