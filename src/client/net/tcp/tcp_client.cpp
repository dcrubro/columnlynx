// tcp_client.cpp - TCP Client for ColumnLynx
// Copyright (C) 2026 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#include <columnlynx/client/net/tcp/tcp_client.hpp>
//#include <arpa/inet.h>

namespace ColumnLynx::Net::TCP {
    TCPClient::TCPClient(asio::io_context& ioContext, const std::string& host, const std::string& port)
        : mResolver(ioContext),
          mSocket(ioContext),
          mHost(host),
          mPort(port),
          mHeartbeatTimer(mSocket.get_executor()),
          mLastHeartbeatReceived(std::chrono::steady_clock::now()),
          mLastHeartbeatSent(std::chrono::steady_clock::now())
    {
        if (!ClientSession::getInstance().getSodiumWrapper()) {
            throw std::runtime_error("ClientSession sodium wrapper is not initialized");
        }
    }

    void TCPClient::start() {
        auto self = shared_from_this();
        mResolver.async_resolve(mHost, mPort,
            [this, self](asio::error_code ec, tcp::resolver::results_type endpoints) {
                if (!ec) {
                    asio::async_connect(mSocket, endpoints,
                        [this, self](asio::error_code ec, const tcp::endpoint&) {
                            if (!ec) {
                                mConnected.store(true, std::memory_order_relaxed);
                                Utils::log("Client connected.");
                                mHandler = std::make_shared<MessageHandler>(std::move(mSocket));
                                mHandler->onMessage([weakSelf = weak_from_this()](AnyMessageType type, const std::string& data) {
                                    if (auto self = weakSelf.lock()) {
                                        self->mHandleMessage(static_cast<ServerMessageType>(MessageHandler::toUint8(type)), data);
                                    }
                                });
                                // Close only after peer FIN to avoid RSTs
                                mHandler->onDisconnect([weakSelf = weak_from_this()](const asio::error_code& ec) {
                                    auto self = weakSelf.lock();
                                    if (!self) {
                                        return;
                                    }
                                    asio::error_code ec2;
                                    if (self->mHandler) {
                                        self->mHandler->socket().close(ec2);
                                    }
                                    self->mConnected.store(false, std::memory_order_relaxed);
                                    Utils::log(std::string("Server disconnected: ") + ec.message());
                                });
                                mHandler->start();
                                
                                // Init connection handshake
                                Utils::log("Sending handshake init to server.");

                                // Check if hostname or IPv4/IPv6
                                try {
                                    asio::ip::make_address(mHost);
                                    self->mIsHostDomain = false; // IPv4 or IPv6 literal
                                } catch (const asio::system_error&) {
                                    self->mIsHostDomain = true;  // hostname / domain
                                }


                                std::vector<uint8_t> payload;
                                payload.reserve(1 + crypto_box_PUBLICKEYBYTES);
                                payload.push_back(Utils::protocolVersion());
                                Utils::log("Using protocol version: " + std::to_string(Utils::protocolVersion()));
                                /*payload.insert(payload.end(),
                                    mLibSodiumWrapper->getXPublicKey(),
                                    mLibSodiumWrapper->getXPublicKey() + crypto_box_PUBLICKEYBYTES
                                );*/

                                const auto& mLibSodiumWrapper = ClientSession::getInstance().getSodiumWrapper();
                                payload.insert(payload.end(),
                                    mLibSodiumWrapper->getPublicKey(),
                                    mLibSodiumWrapper->getPublicKey() + crypto_sign_PUBLICKEYBYTES
                                );

                                mHandler->sendMessage(ClientMessageType::HANDSHAKE_INIT, Utils::uint8ArrayToString(payload.data(), payload.size()));
                            
                                mStartHeartbeat();
                            } else {
                                if (!NetHelper::isExpectedDisconnect(ec)) {
                                    Utils::error("Client connect failed: " + ec.message());
                                }
                            }
                        });
                } else {
                    Utils::error("Client resolve failed: " + ec.message());
                }
            });
    }

    void TCPClient::sendMessage(ClientMessageType type, const std::string& data) {
        if (!mConnected.load(std::memory_order_relaxed)) {
            Utils::error("Cannot send message, client not connected.");
            return;
        }

        if (mHandler) {
            asio::post(mHandler->socket().get_executor(), [self = shared_from_this(), type, data]() {
                self->mHandler->sendMessage(type, data);
            });
        }
    }

    void TCPClient::disconnect(bool echo) {
        if (mConnected.load(std::memory_order_relaxed) && mHandler) {
            if (echo) {
                mHandler->sendMessage(ClientMessageType::GRACEFUL_DISCONNECT, "Goodbye");
            }

            asio::error_code ec;
            mHeartbeatTimer.cancel();

            // Half-close: stop sending, keep reading until peer FIN
            mHandler->socket().shutdown(tcp::socket::shutdown_send, ec);
            if (ec) {
                Utils::error("Error during socket shutdown: " + ec.message());
            }

            // Do not close immediately; rely on onDisconnect to finalize
            Utils::log("Client initiated graceful disconnect (half-close).");
        }
    }

    bool TCPClient::isHandshakeComplete() const {
        return mHandshakeComplete.load(std::memory_order_relaxed);
    }

    bool TCPClient::isConnected() const {
        return mConnected.load(std::memory_order_relaxed);
    }

    void TCPClient::mStartHeartbeat() {
        auto self = shared_from_this();
        mHeartbeatTimer.expires_after(std::chrono::seconds(5));
        mHeartbeatTimer.async_wait([self](const asio::error_code& ec) {
            if (ec == asio::error::operation_aborted) {
                return; // Timer was cancelled
            }

            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - self->mLastHeartbeatReceived).count();

            if (elapsed >= 15) { // 3 missed heartbeats
                Utils::error("Missed 3 heartbeats. I think the other party might have died! Disconnecting.");
                
                // Close sockets forcefully, server is dead
                asio::error_code ec;
                if (self->mHandler) {
                    self->mHandler->socket().shutdown(tcp::socket::shutdown_both, ec);
                    self->mHandler->socket().close(ec);
                }
                self->mConnected.store(false, std::memory_order_relaxed);
                
                ClientSession::getInstance().setAESKey({}); // Clear AES key with all zeros
                ClientSession::getInstance().setSessionID(0);

                return;
            }

            self->sendMessage(ClientMessageType::HEARTBEAT);
            Utils::debug("Sent HEARTBEAT to server.");
            self->mLastHeartbeatSent = std::chrono::steady_clock::now();
            
            self->mStartHeartbeat(); // Recursive
        });
    }

    void TCPClient::mHandleMessage(ServerMessageType type, const std::string& data) {
        switch (type) {
            case ServerMessageType::HANDSHAKE_IDENTIFY: {
                    if (data.size() != sizeof(mServerPublicKey)) {
                        Utils::warn("HANDSHAKE_IDENTIFY has invalid size: " + std::to_string(data.size()));
                        disconnect();
                        return;
                    }

                    std::memcpy(mServerPublicKey, data.data(), sizeof(mServerPublicKey));
                    std::string hexServerPub = Utils::bytesToHexString(mServerPublicKey, 32);
                    Utils::log("Received server identity. Public Key: " + hexServerPub);

                    // Verify pubkey against whitelisted_keys
                    const std::string& configPath = ClientSession::getInstance().getConfigPath();
                    std::vector<std::string> whitelistedKeys = Utils::getWhitelistedKeys(configPath);
                    if (std::find(whitelistedKeys.begin(), whitelistedKeys.end(), Utils::bytesToHexString(mServerPublicKey, 32)) == whitelistedKeys.end()) { // Key verification is handled in later steps of the handshake
                        if (!ClientSession::getInstance().isInsecureMode()) {
                            Utils::error("Server public key not in whitelisted_keys. Terminating connection.");
                            disconnect();
                            return;
                        }

                        Utils::warn("Server public key not in whitelisted_keys, but continuing due to insecure mode.");
                    }

                    // Generate and send challenge
                    Utils::log("Sending challenge to server.");
                    mSubmittedChallenge = Utils::LibSodiumWrapper::generateRandom256Bit(); // Temporarily store the challenge to verify later
                    mHandler->sendMessage(ClientMessageType::HANDSHAKE_CHALLENGE, Utils::uint8ArrayToString(mSubmittedChallenge));
                }

                break;
            case ServerMessageType::HANDSHAKE_CHALLENGE_RESPONSE:
                Utils::log("Received challenge response from server.");
                {
                    // Verify the signature
                    Signature sig{};
                    if (data.size() != sig.size()) {
                        Utils::warn("HANDSHAKE_CHALLENGE_RESPONSE has invalid size: " + std::to_string(data.size()));
                        disconnect();
                        return;
                    }

                    std::memcpy(sig.data(), data.data(), sig.size());
                    if (Utils::LibSodiumWrapper::verifyMessage(mSubmittedChallenge.data(), mSubmittedChallenge.size(), sig, mServerPublicKey)) {
                        Utils::log("Challenge response verified successfully.");
                        
                        // Convert the server's public key to Curve25519 for encryption
                        AsymPublicKey serverXPubKey{};
                        int r = crypto_sign_ed25519_pk_to_curve25519(serverXPubKey.data(), mServerPublicKey);
                        if (r != 0) {
                            Utils::error("Failed to convert server signing key to encryption key! Killing connection.");
                            disconnect();
                            return;
                        }

                        // Generate AES key and send confirmation
                        mConnectionAESKey = Utils::LibSodiumWrapper::generateRandom256Bit();
                        ClientSession::getInstance().setAESKey(mConnectionAESKey);
                        AsymNonce nonce{};
                        randombytes_buf(nonce.data(), nonce.size());

                        // TODO: This is pretty redundant, it should return the required type directly
                        std::array<uint8_t, 32> arrayPrivateKey;
                        std::copy(ClientSession::getInstance().getSodiumWrapper()->getXPrivateKey(),
                                  ClientSession::getInstance().getSodiumWrapper()->getXPrivateKey() + 32,
                                  arrayPrivateKey.begin());

                        std::vector<uint8_t> encr = Utils::LibSodiumWrapper::encryptAsymmetric(
                            mConnectionAESKey.data(), mConnectionAESKey.size(),
                            nonce,
                            serverXPubKey,
                            arrayPrivateKey
                        );

                        std::vector<uint8_t> payload;
                        payload.reserve(nonce.size() + encr.size());
                        payload.insert(payload.end(), nonce.begin(), nonce.end());
                        payload.insert(payload.end(), encr.begin(), encr.end());

                        mHandler->sendMessage(ClientMessageType::HANDSHAKE_EXCHANGE_KEY, Utils::uint8ArrayToString(payload.data(), payload.size()));
                    } else {
                        Utils::error("Challenge response verification failed. Terminating connection.");
                        disconnect();
                    }
                }

                break;
            case ServerMessageType::HANDSHAKE_EXCHANGE_KEY_CONFIRM:
                Utils::log("Received handshake exchange key confirmation from server.");
                // Decrypt the session ID using the established AES key
                {
                    Nonce symNonce{}; // All zeros
                    std::vector<uint8_t> ciphertext(data.begin(), data.end());
                    std::vector<uint8_t> decrypted = Utils::LibSodiumWrapper::decryptMessage(
                        ciphertext.data(), ciphertext.size(),
                        mConnectionAESKey, symNonce
                    );

                    if (decrypted.size() != sizeof(mConnectionSessionID) + sizeof(Protocol::TunConfig)) {
                        Utils::error("Decrypted config has invalid size. Terminating connection.");
                        disconnect();
                        return;
                    }

                    std::memcpy(&mConnectionSessionID, decrypted.data(), sizeof(mConnectionSessionID));
                    std::memcpy(&mTunConfig, decrypted.data() + sizeof(mConnectionSessionID), sizeof(Protocol::TunConfig));

                    mConnectionSessionID = ntohl(mConnectionSessionID);

                    Utils::log("Connection established with Session ID: " + std::to_string(mConnectionSessionID));
                
                    ClientSession::getInstance().setSessionID(mConnectionSessionID);

                    uint32_t clientIP = ntohl(mTunConfig.clientIP);
                    uint32_t serverIP = ntohl(mTunConfig.serverIP);
                    uint8_t prefixLen = mTunConfig.prefixLength;
                    uint16_t mtu = mTunConfig.mtu;

                    const auto& mTun = ClientSession::getInstance().getVirtualInterface();
                    if (mTun) {
                        mTun->configureIP(clientIP, serverIP, prefixLen, mtu);
                    }

                    mHandshakeComplete.store(true, std::memory_order_relaxed);
                }
            
                break;
            case ServerMessageType::HEARTBEAT:
                Utils::debug("Received HEARTBEAT from server.");
                mHandler->sendMessage(ClientMessageType::HEARTBEAT_ACK, ""); // Send ACK
                break;
            case ServerMessageType::HEARTBEAT_ACK:
                Utils::debug("Received HEARTBEAT_ACK from server.");
                mLastHeartbeatReceived = std::chrono::steady_clock::now();
                mMissedHeartbeats = 0; // Reset missed heartbeat count
                break;
            case ServerMessageType::GRACEFUL_DISCONNECT:
                Utils::log("Server is disconnecting: " + data);
                if (mConnected.load(std::memory_order_relaxed)) { // Prevent Recursion
                    disconnect(false);
                }
                break;
            case ServerMessageType::KILL_CONNECTION:
                Utils::warn("Server is killing the connection: " + data);
                if (mConnected.load(std::memory_order_relaxed)) {
                    disconnect(false);
                }
                break;
            default:
                Utils::log("Received unknown message type from server.");
                break;
        }
    }
}