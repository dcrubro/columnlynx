// main.cpp - Server entry point for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the GPLv3 license. See LICENSE for details.

#include <asio/asio.hpp>
#include <iostream>
#include <columnlynx/common/utils.hpp>
#include <columnlynx/common/panic_handler.hpp>
#include <columnlynx/server/net/tcp/tcp_server.hpp>
#include <columnlynx/common/libsodium_wrapper.hpp>

using asio::ip::tcp;
using namespace ColumnLynx::Utils;
using namespace ColumnLynx::Net::TCP;

int main(int argc, char** argv) {
    PanicHandler::init();

    try {
        // TODO: Catch SIGINT and SIGTERM for graceful shutdown

        // Generate a temporary keypair, replace with actual CA signed keys later (Note, these are stored in memory)
        LibSodiumWrapper sodiumWrapper = LibSodiumWrapper();

        asio::io_context io;
        auto server = std::make_shared<TCPServer>(io, serverPort());

        // Run the IO context in a separate thread
        std::thread ioThread([&io]() {
            io.run();
        });

        ioThread.join();

        log("Server started on port " + std::to_string(serverPort()));
    } catch (const std::exception& e) {
        error("Server error: " + std::string(e.what()));
    }
}