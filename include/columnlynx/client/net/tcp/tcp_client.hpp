// tcp_client.hpp - TCP Client for ColumnLynx
// Copyright (C) 2026 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#pragma once

#include <asio.hpp>
#include <columnlynx/common/net/tcp/tcp_message_handler.hpp>
#include <columnlynx/common/net/tcp/tcp_message_type.hpp>
#include <columnlynx/common/net/tcp/net_helper.hpp>
#include <columnlynx/common/utils.hpp>
#include <columnlynx/common/libsodium_wrapper.hpp>
#include <array>
#include <atomic>
#include <algorithm>
#include <vector>
#include <string>
#include <columnlynx/common/net/protocol_structs.hpp>
#include <columnlynx/common/net/virtual_interface.hpp>
#include <columnlynx/client/client_session.hpp>

using asio::ip::tcp;

namespace ColumnLynx::Net::TCP {
    class TCPClient : public std::enable_shared_from_this<TCPClient> {
        public:
            TCPClient(asio::io_context& ioContext,
                      const std::string& host,
                      const std::string& port);

            // Starts the TCP Client and initiaties the handshake
            void start();
            // Sends a TCP message to the server
            void sendMessage(ClientMessageType type, const std::string& data = "");
            // Attempt to gracefully disconnect from the server
            void disconnect(bool echo = true);

            // Get the handshake status
            bool isHandshakeComplete() const;
            // Get the connection status
            bool isConnected() const;

        private:
            // Start the heartbeat routine
            void mStartHeartbeat();
            // Handle an incoming TCP message
            void mHandleMessage(ServerMessageType type, const std::string& data);

            // TODO: Move ptrs to smart ptrs

            std::atomic<bool> mConnected{false};
            std::atomic<bool> mHandshakeComplete{false};
            tcp::resolver mResolver;
            tcp::socket mSocket;
            std::shared_ptr<MessageHandler> mHandler;
            std::string mHost, mPort;
            uint8_t mServerPublicKey[32]; // Assuming 256-bit public key
            std::array<uint8_t, 32> mSubmittedChallenge{};
            uint32_t mConnectionSessionID;
            SymmetricKey mConnectionAESKey;
            asio::steady_timer mHeartbeatTimer;
            std::chrono::steady_clock::time_point mLastHeartbeatReceived;
            std::chrono::steady_clock::time_point mLastHeartbeatSent;
            int mMissedHeartbeats = 0;
            bool mIsHostDomain;
            Protocol::TunConfig mTunConfig;
    };
}