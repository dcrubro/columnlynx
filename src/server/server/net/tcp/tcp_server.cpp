// tcp_server.cpp - TCP Server for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the GPLv3 license. See LICENSE for details.

#pragma once

#include <columnlynx/server/net/tcp/tcp_server.hpp>

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>
#include <memory>
#include <unordered_set>
#include <asio/asio.hpp>
#include <columnlynx/common/net/tcp/tcp_message_type.hpp>
#include <columnlynx/common/net/tcp/net_helper.hpp>
#include <columnlynx/common/utils.hpp>

namespace ColumnLynx::Net::TCP {

    void TCPServer::mStartAccept() {
        mAcceptor.async_accept(
            [this](asio::error_code ec, asio::ip::tcp::socket socket) {
                if (!NetHelper::isExpectedDisconnect(ec)) {
                    auto client = TCPConnection::create(std::move(socket),
                        mSodiumWrapper,
                        [this](std::shared_ptr<TCPConnection> c) {
                            mClients.erase(c);
                            Utils::log("Client removed.");
                        });
                    
                    mClients.insert(client);
                    client->start();

                    Utils::log("Accepted new client connection.");
                } else {
                    Utils::error("Accept failed: " + ec.message());
                }

                TCPServer::mStartAccept(); // Accept next
            }
        );
    }

}