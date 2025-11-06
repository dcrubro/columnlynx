// tcp_server.hpp - TCP Server for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the GPLv3 license. See LICENSE for details.

#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>
#include <memory>
#include <unordered_set>
#include <new>
#include <asio/asio.hpp>
#include <columnlynx/common/net/tcp/tcp_message_type.hpp>
#include <columnlynx/common/utils.hpp>
#include <columnlynx/server/net/tcp/tcp_connection.hpp>
#include <columnlynx/common/libsodium_wrapper.hpp>

namespace ColumnLynx::Net::TCP {

    class TCPServer {
        public:
            TCPServer(asio::io_context& ioContext, uint16_t port, Utils::LibSodiumWrapper* sodiumWrapper)
                : mIoContext(ioContext), mAcceptor(ioContext, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port)), mSodiumWrapper(sodiumWrapper)
            {
                Utils::log("Started TCP server on port " + std::to_string(port));
                mStartAccept();
            }

        private:
            void mStartAccept();
            asio::io_context &mIoContext;
            asio::ip::tcp::acceptor mAcceptor;
            std::unordered_set<TCPConnection::pointer> mClients;
            Utils::LibSodiumWrapper *mSodiumWrapper;
    };

}