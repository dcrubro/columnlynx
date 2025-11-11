// main.cpp - Server entry point for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#include <asio/asio.hpp>
#include <iostream>
#include <columnlynx/common/utils.hpp>
#include <columnlynx/common/panic_handler.hpp>
#include <columnlynx/server/net/tcp/tcp_server.hpp>
#include <columnlynx/server/net/udp/udp_server.hpp>
#include <columnlynx/common/libsodium_wrapper.hpp>
#include <unordered_set>

using asio::ip::tcp;
using namespace ColumnLynx::Utils;
using namespace ColumnLynx::Net::TCP;
using namespace ColumnLynx::Net::UDP;

volatile sig_atomic_t done = 0;

/*void signalHandler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        log("Received termination signal. Shutting down server gracefully.");
        done = 1;
    }
}*/

int main(int argc, char** argv) {
    PanicHandler::init();

    try {
        // Catch SIGINT and SIGTERM for graceful shutdown
        /*struct sigaction action;
        memset(&action, 0, sizeof(struct sigaction));
        action.sa_handler = signalHandler;
        sigaction(SIGINT, &action, nullptr);
        sigaction(SIGTERM, &action, nullptr);*/

        log("ColumnLynx Server, Version " + getVersion());
        log("This software is licensed under the GPLv2 only OR the GPLv3. See LICENSE for details.");

        // Generate a temporary keypair, replace with actual CA signed keys later (Note, these are stored in memory)
        LibSodiumWrapper sodiumWrapper = LibSodiumWrapper();
        log("Server public key: " + bytesToHexString(sodiumWrapper.getPublicKey(), crypto_sign_PUBLICKEYBYTES));
        //log("Server private key: " + bytesToHexString(sodiumWrapper.getPrivateKey(), crypto_sign_SECRETKEYBYTES)); // TEMP, remove later

        bool hostRunning = true;

        asio::io_context io;

        auto server = std::make_shared<TCPServer>(io, serverPort(), &sodiumWrapper, &hostRunning);
        auto udpServer = std::make_shared<UDPServer>(io, serverPort(), &hostRunning);

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
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
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