// tcp_server.cpp - TCP Server for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

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
                if (ec) {
                    if (ec == asio::error::operation_aborted) {
                        // Acceptor was cancelled/closed during shutdown
                        return;
                    }
                    Utils::error("Accept failed: " + ec.message());
                    // Try again only if still running
                    if (mHostRunning && *mHostRunning && mAcceptor.is_open())
                        mStartAccept();
                    return;
                }
            
                auto client = TCPConnection::create(
                    std::move(socket),
                    mSodiumWrapper,
                    [this](std::shared_ptr<TCPConnection> c) {
                        mClients.erase(c);
                        Utils::log("Client removed.");
                    }
                );
                mClients.insert(client);
                client->start();
                Utils::log("Accepted new client connection.");
            
                if (mHostRunning && *mHostRunning && mAcceptor.is_open())
                    mStartAccept();
            }
        );
    }

    void TCPServer::stop() {
        // Stop accepting
        if (mAcceptor.is_open()) {
            asio::error_code ec;
            mAcceptor.cancel(ec);
            mAcceptor.close(ec);
            Utils::log("TCP Acceptor closed.");
        }

        // Snapshot to avoid iterator invalidation while callbacks erase()
        std::vector<std::shared_ptr<TCPConnection>> snapshot(mClients.begin(), mClients.end());
        for (auto& client : snapshot) {
            try {
                client->disconnect(); // should shutdown+close the socket
                Utils::log("GRACEFUL_DISCONNECT sent to session: " + std::to_string(client->getSessionID()));
            } catch (const std::exception& e) {
                Utils::error(std::string("Error disconnecting client: ") + e.what());
            }
        }
        // Let the erase callback run as sockets close
        // Do NOT destroy server while io handlers may still reference it
    }
}