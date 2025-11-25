// tcp_client.cpp - TCP Client for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#include <columnlynx/client/net/tcp/tcp_client.hpp>
#include <arpa/inet.h>

namespace ColumnLynx::Net::TCP {
    void TCPClient::start() {
        auto self = shared_from_this();
        mResolver.async_resolve(mHost, mPort,
            [this, self](asio::error_code ec, tcp::resolver::results_type endpoints) {
                if (!ec) {
                    asio::async_connect(mSocket, endpoints,
                        [this, self](asio::error_code ec, const tcp::endpoint&) {
                            if (!NetHelper::isExpectedDisconnect(ec)) {
                                mConnected = true;
                                Utils::log("Client connected.");
                                mHandler = std::make_shared<MessageHandler>(std::move(mSocket));
                                mHandler->onMessage([this](AnyMessageType type, const std::string& data) {
                                    mHandleMessage(static_cast<ServerMessageType>(MessageHandler::toUint8(type)), data);
                                });
                                mHandler->start();
                                
                                // Init connection handshake
                                Utils::log("Sending handshake init to server.");

                                // Check if hostname or IPv4/IPv6
                                sockaddr_in addr4{};
                                sockaddr_in6 addr6{};
                                self->mIsHostDomain = inet_pton(AF_INET, mHost.c_str(), (void*)(&addr4)) != 1 && inet_pton(AF_INET6, mHost.c_str(), (void*)(&addr6)) != 1; // Voodoo black magic

                                std::vector<uint8_t> payload;
                                payload.reserve(1 + crypto_box_PUBLICKEYBYTES);
                                payload.push_back(Utils::protocolVersion());
                                /*payload.insert(payload.end(),
                                    mLibSodiumWrapper->getXPublicKey(),
                                    mLibSodiumWrapper->getXPublicKey() + crypto_box_PUBLICKEYBYTES
                                );*/
                                payload.insert(payload.end(),
                                    mLibSodiumWrapper->getPublicKey(),
                                    mLibSodiumWrapper->getPublicKey() + crypto_sign_PUBLICKEYBYTES
                                );

                                mHandler->sendMessage(ClientMessageType::HANDSHAKE_INIT, Utils::uint8ArrayToString(payload.data(), payload.size()));
                            
                                mStartHeartbeat();
                            } else {
                                Utils::error("Client connect failed: " + ec.message());
                            }
                        });
                } else {
                    Utils::error("Client resolve failed: " + ec.message());
                }
            });
    }

    void TCPClient::sendMessage(ClientMessageType type, const std::string& data) {
        if (!mConnected) {
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
        if (mConnected && mHandler) {
            if (echo) {
                mHandler->sendMessage(ClientMessageType::GRACEFUL_DISCONNECT, "Goodbye");
            }

            asio::error_code ec;
            mHeartbeatTimer.cancel();

            mHandler->socket().shutdown(tcp::socket::shutdown_both, ec);
            if (ec) {
                Utils::error("Error during socket shutdown: " + ec.message());
            }

            mHandler->socket().close(ec);
            if (ec) {
                Utils::error("Error during socket close: " + ec.message());
            }

            mConnected = false;
            Utils::log("Client disconnected.");
        }
    }

    bool TCPClient::isHandshakeComplete() const {
        return mHandshakeComplete;
    }

    bool TCPClient::isConnected() const {
        return mConnected;
    }

    void TCPClient::mStartHeartbeat() {
        auto self = shared_from_this();
        mHeartbeatTimer.expires_after(std::chrono::seconds(5));
        mHeartbeatTimer.async_wait([this, self](const asio::error_code& ec) {
            if (ec == asio::error::operation_aborted) {
                return; // Timer was cancelled
            }

            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - self->mLastHeartbeatReceived).count();

            if (elapsed >= 15) { // 3 missed heartbeats
                Utils::error("Missed 3 heartbeats. I think the other party might have died! Disconnecting.");
                
                // Close sockets forcefully, server is dead
                asio::error_code ec;
                mHandler->socket().shutdown(tcp::socket::shutdown_both, ec);
                mHandler->socket().close(ec);
                mConnected = false;

                mGlobalKeyRef = nullptr;
                if (mSessionIDRef) {
                    *mSessionIDRef = 0;
                }

                return;
            }

            self->sendMessage(ClientMessageType::HEARTBEAT);
            Utils::log("Sent HEARTBEAT to server.");
            self->mLastHeartbeatSent = std::chrono::steady_clock::now();
            
            self->mStartHeartbeat(); // Recursive
        });
    }

    void TCPClient::mHandleMessage(ServerMessageType type, const std::string& data) {
        switch (type) {
            case ServerMessageType::HANDSHAKE_IDENTIFY: {
                    Utils::log("Received server identity: " + data);
                    std::memcpy(mServerPublicKey, data.data(), std::min(data.size(), sizeof(mServerPublicKey)));

                    // Convert key (uint8_t raw array) to vector
                    std::vector<uint8_t> serverPublicKeyVec(std::begin(mServerPublicKey), std::end(mServerPublicKey));

                    // Verify server public key
                    if (!Utils::LibSodiumWrapper::verifyCertificateWithSystemCAs(serverPublicKeyVec)) {
                        if (!(*mInsecureMode)) {
                            Utils::error("Server public key verification failed. Terminating connection.");
                            disconnect();
                            return;
                        }

                        Utils::warn("Warning: Server public key verification failed, but continuing due to insecure mode.");
                    }

                    // Extract and verify hostname from certificate if not IP
                    if (mIsHostDomain) {
                        std::vector<std::string> certHostnames = Utils::LibSodiumWrapper::getCertificateHostname(serverPublicKeyVec);

                        // Temp: print extracted hostnames if any
                        for (const auto& hostname : certHostnames) {
                            Utils::log("Extracted hostname from certificate: " + hostname);
                        }

                        if (certHostnames.empty() || std::find(certHostnames.begin(), certHostnames.end(), mHost) == certHostnames.end()) {
                            if (!(*mInsecureMode)) {
                                Utils::error("Server hostname verification failed. Terminating connection.");
                                disconnect();
                                return;
                            }

                            Utils::warn("Warning: Server hostname verification failed, but continuing due to insecure mode.");
                        }
                    } else {
                        Utils::warn("Connecting via IP address, I can't verify the server's identity! You might be getting MITM'd!");
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
                    std::memcpy(sig.data(), data.data(), std::min(data.size(), sig.size()));
                    if (Utils::LibSodiumWrapper::verifyMessage(mSubmittedChallenge.data(), mSubmittedChallenge.size(), sig, mServerPublicKey)) {
                        Utils::log("Challenge response verified successfully.");
                        
                        // Convert the server's public key to Curve25519 for encryption
                        AsymPublicKey serverXPubKey{};
                        crypto_sign_ed25519_pk_to_curve25519(serverXPubKey.data(), mServerPublicKey);

                        // Generate AES key and send confirmation
                        mConnectionAESKey = Utils::LibSodiumWrapper::generateRandom256Bit();
                        if (mGlobalKeyRef) { // Copy to the global reference
                            std::copy(mConnectionAESKey.begin(), mConnectionAESKey.end(), mGlobalKeyRef->begin());
                        }
                        AsymNonce nonce{};
                        randombytes_buf(nonce.data(), nonce.size());

                        // TODO: This is pretty redundant, it should return the required type directly
                        std::array<uint8_t, 32> arrayPrivateKey;
                        std::copy(mLibSodiumWrapper->getXPrivateKey(),
                                  mLibSodiumWrapper->getXPrivateKey() + 32,
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

                    mConnectionSessionID = Utils::cbe64toh(mConnectionSessionID);

                    Utils::log("Connection established with Session ID: " + std::to_string(mConnectionSessionID));
                
                    if (mSessionIDRef) { // Copy to the global reference
                        *mSessionIDRef = mConnectionSessionID;
                    }

                    uint32_t clientIP = ntohl(mTunConfig.clientIP);
                    uint32_t serverIP = ntohl(mTunConfig.serverIP);
                    uint8_t prefixLen = mTunConfig.prefixLength;
                    uint16_t mtu = mTunConfig.mtu;

                    if (mTun) {
                        mTun->configureIP(clientIP, serverIP, prefixLen, mtu);
                    }

                    mHandshakeComplete = true;
                }
            
                break;
            case ServerMessageType::HEARTBEAT:
                Utils::log("Received HEARTBEAT from server.");
                mHandler->sendMessage(ClientMessageType::HEARTBEAT_ACK, ""); // Send ACK
                break;
            case ServerMessageType::HEARTBEAT_ACK:
                Utils::log("Received HEARTBEAT_ACK from server.");
                mLastHeartbeatReceived = std::chrono::steady_clock::now();
                mMissedHeartbeats = 0; // Reset missed heartbeat count
                break;
            case ServerMessageType::GRACEFUL_DISCONNECT:
                Utils::log("Server is disconnecting: " + data);
                if (mConnected) { // Prevent Recursion
                    disconnect(false);
                }
                break;
            default:
                Utils::log("Received unknown message type from server.");
                break;
        }
    }
}