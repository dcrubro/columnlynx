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
#include <unordered_map>
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
            {
                // Preload the config map
                mRawClientConfig = Utils::getConfigMap("client_config");

                if (!mRawClientConfig.empty()) {
                    Utils::debug("Loading the keys");

                    PrivateKey sk;
                    PublicKey pk;
                    std::copy_n(Utils::hexStringToBytes(mRawClientConfig.find("CLIENT_PRIVATE_KEY")->second).begin(), sk.size(), sk.begin()); // This is extremely stupid, but the C++ compiler has forced my hand (I would've just used to_array, but fucking asio decls)
                    std::copy_n(Utils::hexStringToBytes(mRawClientConfig.find("CLIENT_PUBLIC_KEY")->second).begin(), pk.size(), pk.begin());

                    mLibSodiumWrapper->setKeys(pk, sk);

                    Utils::debug("Newly-Loaded Public Key: " + Utils::bytesToHexString(mLibSodiumWrapper->getPublicKey(), 32));
                    Utils::debug("Newly-Loaded Private Key: " + Utils::bytesToHexString(mLibSodiumWrapper->getPrivateKey(), 64));
                    Utils::debug("Public Encryption Key: " + Utils::bytesToHexString(mLibSodiumWrapper->getXPublicKey(), 32));
                }
            }

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
            std::unordered_map<std::string, std::string> mRawClientConfig;
    };
}