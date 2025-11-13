// tcp_client.hpp - TCP Client for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#pragma once

#include <asio/asio.hpp>
#include <columnlynx/common/net/tcp/tcp_message_handler.hpp>
#include <columnlynx/common/net/tcp/tcp_message_type.hpp>
#include <columnlynx/common/net/tcp/net_helper.hpp>
#include <columnlynx/common/utils.hpp>
#include <columnlynx/common/libsodium_wrapper.hpp>
#include <array>
#include <algorithm>
#include <vector>
#include <columnlynx/common/net/protocol_structs.hpp>
#include <columnlynx/common/net/virtual_interface.hpp>

using asio::ip::tcp;

namespace ColumnLynx::Net::TCP {
    class TCPClient : public std::enable_shared_from_this<TCPClient> {
        public:
            TCPClient(asio::io_context& ioContext,
                      const std::string& host,
                      const std::string& port,
                      Utils::LibSodiumWrapper* sodiumWrapper,
                      std::array<uint8_t, 32>* aesKey,
                      uint64_t* sessionIDRef,
                      bool* insecureMode,
                      std::shared_ptr<VirtualInterface> tun = nullptr)
                :
                mResolver(ioContext),
                mSocket(ioContext),
                mHost(host),
                mPort(port),
                mLibSodiumWrapper(sodiumWrapper),
                mGlobalKeyRef(aesKey),
                mSessionIDRef(sessionIDRef),
                mInsecureMode(insecureMode),
                mHeartbeatTimer(mSocket.get_executor()),
                mLastHeartbeatReceived(std::chrono::steady_clock::now()),
                mLastHeartbeatSent(std::chrono::steady_clock::now()),
                mTun(tun)
            {}

            void start();
            void sendMessage(ClientMessageType type, const std::string& data = "");
            void disconnect(bool echo = true);

            bool isHandshakeComplete() const;
            bool isConnected() const;

        private:
            void mStartHeartbeat();
            void mHandleMessage(ServerMessageType type, const std::string& data);

            bool mConnected = false;
            bool mHandshakeComplete = false;
            tcp::resolver mResolver;
            tcp::socket mSocket;
            std::shared_ptr<MessageHandler> mHandler;
            std::string mHost, mPort;
            uint8_t mServerPublicKey[32]; // Assuming 256-bit public key
            std::array<uint8_t, 32> mSubmittedChallenge{};
            Utils::LibSodiumWrapper* mLibSodiumWrapper;
            uint64_t mConnectionSessionID;
            SymmetricKey mConnectionAESKey;
            std::array<uint8_t, 32>* mGlobalKeyRef; // Reference to global AES key
            uint64_t* mSessionIDRef; // Reference to global Session ID
            bool* mInsecureMode; // Reference to insecure mode flag
            asio::steady_timer mHeartbeatTimer;
            std::chrono::steady_clock::time_point mLastHeartbeatReceived;
            std::chrono::steady_clock::time_point mLastHeartbeatSent;
            int mMissedHeartbeats = 0;
            bool mIsHostDomain;
            Protocol::TunConfig mTunConfig;
            std::shared_ptr<VirtualInterface> mTun = nullptr;
    };
}