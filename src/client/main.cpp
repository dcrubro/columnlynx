// main.cpp - Client entry point for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the GPLv3 license. See LICENSE for details.

#include <asio/asio.hpp>
#include <csignal>
#include <iostream>
#include <columnlynx/common/utils.hpp>
#include <columnlynx/common/panic_handler.hpp>
#include <columnlynx/client/net/tcp/tcp_client.hpp>
#include <columnlynx/client/net/udp/udp_client.hpp>

using asio::ip::tcp;
using namespace ColumnLynx::Utils;

volatile sig_atomic_t done = 0;

void signalHandler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        log("Received termination signal. Shutting down client.");
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

    try {
        log("ColumnLynx Client, Version " + getVersion());
        log("This software is licensed under the GPLv3. See LICENSE for details.");

        LibSodiumWrapper sodiumWrapper = LibSodiumWrapper();

        std::array<uint8_t, 32> aesKey = {0}; // Defualt zeroed state until modified by handshake
        uint64_t sessionID = 0;

        asio::io_context io;
        auto client = std::make_shared<ColumnLynx::Net::TCP::TCPClient>(io, "127.0.0.1", std::to_string(serverPort()), &sodiumWrapper, &aesKey, &sessionID);
        auto udpClient = std::make_shared<ColumnLynx::Net::UDP::UDPClient>(io, "127.0.0.1", std::to_string(serverPort()), &aesKey, &sessionID);

        client->start();
        udpClient->start();

        // Run the IO context in a separate thread
        std::thread ioThread([&io]() {
            io.run();
        });
        ioThread.detach();

        log("Client connected to 127.0.0.1:" + std::to_string(serverPort()));

        // Client is running
        while (!done) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Temp wait

            if (client->isHandshakeComplete()) {
                // Send a test UDP message every 5 seconds after handshake is complete
                static auto lastSendTime = std::chrono::steady_clock::now();
                auto now = std::chrono::steady_clock::now();
                if (std::chrono::duration_cast<std::chrono::seconds>(now - lastSendTime).count() >= 5) {
                    udpClient->sendMessage("Hello from UDP client!");
                    lastSendTime = now;
                }
            }
        }
        log("Client shutting down.");
        client->disconnect();
        io.stop();
        ioThread.join();

    } catch (const std::exception& e) {
        error("Client error: " + std::string(e.what()));
    }
}