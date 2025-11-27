// tcp_connection.hpp - TCP Connection for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#pragma once

#include <iostream>
#include <memory>
#include <string>
#include <ctime>
#include <cstdint>
#include <new>
#include <asio.hpp>
#include <columnlynx/common/net/tcp/tcp_message_type.hpp>
#include <columnlynx/common/net/tcp/tcp_message_handler.hpp>
#include <columnlynx/common/utils.hpp>
#include <columnlynx/common/libsodium_wrapper.hpp>
#include <columnlynx/common/net/session_registry.hpp>
#include <columnlynx/common/net/protocol_structs.hpp>

namespace ColumnLynx::Net::TCP {
    class TCPConnection : public std::enable_shared_from_this<TCPConnection> {
        public:
            using pointer = std::shared_ptr<TCPConnection>;

            static pointer create(
                asio::ip::tcp::socket socket,
                Utils::LibSodiumWrapper* sodiumWrapper,
                std::function<void(pointer)> onDisconnect)
            {
                auto conn = pointer(new TCPConnection(std::move(socket), sodiumWrapper));
                conn->mOnDisconnect = std::move(onDisconnect);
                return conn;
            }

            // Start a TCP Connection (Handler for an incoming connection)
            void start();
            // Send a message to the TCP client
            void sendMessage(ServerMessageType type, const std::string& data = "");
            // Set callback for disconnects
            void setDisconnectCallback(std::function<void(std::shared_ptr<TCPConnection>)> cb);
            // Disconnect the client
            void disconnect();

            // Get the assigned session ID
            uint64_t getSessionID() const;
            // Get the assigned AES key; You should probably access this via the Session Registry instead
            std::array<uint8_t, 32> getAESKey() const;
        
        private:
            TCPConnection(asio::ip::tcp::socket socket, Utils::LibSodiumWrapper* sodiumWrapper)
                :
                mHandler(std::make_shared<MessageHandler>(std::move(socket))),
                mLibSodiumWrapper(sodiumWrapper),
                mHeartbeatTimer(mHandler->socket().get_executor()),
                mLastHeartbeatReceived(std::chrono::steady_clock::now()),
                mLastHeartbeatSent(std::chrono::steady_clock::now())
            {}

            // Start the heartbeat routine
            void mStartHeartbeat();
            // Handle an incoming TCP message
            void mHandleMessage(ClientMessageType type, const std::string& data);

            std::shared_ptr<MessageHandler> mHandler;
            std::function<void(std::shared_ptr<TCPConnection>)> mOnDisconnect;
            Utils::LibSodiumWrapper *mLibSodiumWrapper;
            std::array<uint8_t, 32> mConnectionAESKey;
            uint64_t mConnectionSessionID;
            AsymPublicKey mConnectionPublicKey;
            asio::steady_timer mHeartbeatTimer;
            std::chrono::steady_clock::time_point mLastHeartbeatReceived;
            std::chrono::steady_clock::time_point mLastHeartbeatSent;
            int mMissedHeartbeats = 0;
    };
}