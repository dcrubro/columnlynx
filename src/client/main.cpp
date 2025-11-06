// main.cpp - Client entry point for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the GPLv3 license. See LICENSE for details.

#include <asio/asio.hpp>
#include <csignal>
#include <iostream>
#include <columnlynx/common/utils.hpp>
#include <columnlynx/common/panic_handler.hpp>
#include <columnlynx/client/net/tcp/tcp_client.hpp>

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
        LibSodiumWrapper sodiumWrapper = LibSodiumWrapper();

        asio::io_context io;
        auto client = std::make_shared<ColumnLynx::Net::TCP::TCPClient>(io, "127.0.0.1", std::to_string(serverPort()), &sodiumWrapper);

        client->start();

        // Run the IO context in a separate thread
        std::thread ioThread([&io]() {
            io.run();
        });
        ioThread.detach();

        log("Client connected to 127.0.0.1:" + std::to_string(serverPort()));

        // Client is running
        while (!done) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Temp wait
        }
        log("Client shutting down.");
        client->disconnect();
        io.stop();
        ioThread.join();

    } catch (const std::exception& e) {
        error("Client error: " + std::string(e.what()));
    }
}