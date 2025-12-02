// tcp_connection.cpp - TCP Connection for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#include <columnlynx/server/net/tcp/tcp_connection.hpp>

namespace ColumnLynx::Net::TCP {
    void TCPConnection::start() {
        mHandler->onMessage([this](AnyMessageType type, const std::string& data) {
            mHandleMessage(static_cast<ClientMessageType>(MessageHandler::toUint8(type)), data);
        });

        mHandler->onDisconnect([this](const asio::error_code& ec) {
            Utils::log("Client disconnected: " + mHandler->socket().remote_endpoint().address().to_string() + " - " + ec.message());
            disconnect();
        });

        mHandler->start();
        mStartHeartbeat();

        // Placeholder for message handling setup
        Utils::log("Client connected: " + mHandler->socket().remote_endpoint().address().to_string());
    }

    void TCPConnection::sendMessage(ServerMessageType type, const std::string& data) {
        if (mHandler) {
            mHandler->sendMessage(type, data);
        }
    }

    void TCPConnection::setDisconnectCallback(std::function<void(std::shared_ptr<TCPConnection>)> cb) {
        mOnDisconnect = std::move(cb);
    }

    void TCPConnection::disconnect() {
        std::string ip = mHandler->socket().remote_endpoint().address().to_string();

        mHandler->sendMessage(ServerMessageType::GRACEFUL_DISCONNECT, "Server initiated disconnect.");
        mHeartbeatTimer.cancel();
        asio::error_code ec;
        mHandler->socket().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
        mHandler->socket().close(ec);

        SessionRegistry::getInstance().erase(mConnectionSessionID);
        SessionRegistry::getInstance().deallocIP(mConnectionSessionID);

        Utils::log("Closed connection to " + ip);

        if (mOnDisconnect) {
            mOnDisconnect(shared_from_this());
        }
    }

    uint64_t TCPConnection::getSessionID() const {
        return mConnectionSessionID;
    }

    std::array<uint8_t, 32> TCPConnection::getAESKey() const {
        return mConnectionAESKey;
    }

    void TCPConnection::mStartHeartbeat() {
        auto self = shared_from_this();
        mHeartbeatTimer.expires_after(std::chrono::seconds(5));
        mHeartbeatTimer.async_wait([this, self](const asio::error_code& ec) {
            if (ec == asio::error::operation_aborted) {
                return; // Timer was cancelled
            }

            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - self->mLastHeartbeatReceived).count();

            if (elapsed >= 15) { // 3 missed heartbeats
                Utils::error("Missed 3 heartbeats. I think the other party (client " + std::to_string(self->mConnectionSessionID) + ") might have died! Disconnecting.");
                
                // Remove socket forcefully, client is dead
                asio::error_code ec;
                mHandler->socket().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
                mHandler->socket().close(ec);

                SessionRegistry::getInstance().erase(self->mConnectionSessionID);

                return;
            }

            self->sendMessage(ServerMessageType::HEARTBEAT);
            Utils::debug("Sent HEARTBEAT to client " + std::to_string(self->mConnectionSessionID));
            self->mLastHeartbeatSent = now;

            self->mStartHeartbeat(); // Recursive
        });
    }

    void TCPConnection::mHandleMessage(ClientMessageType type, const std::string& data) {
        std::string reqAddr = mHandler->socket().remote_endpoint().address().to_string();
    
        switch (type) {
            case ClientMessageType::HANDSHAKE_INIT: {
                Utils::log("Received HANDSHAKE_INIT from " + reqAddr);

                if (data.size() < 1 + crypto_box_PUBLICKEYBYTES) {
                    Utils::warn("HANDSHAKE_INIT from " + reqAddr + " is too short.");
                    disconnect();
                    return;
                }

                uint8_t clientProtoVer = static_cast<uint8_t>(data[0]);
                if (clientProtoVer != Utils::protocolVersion()) {
                    Utils::warn("Client protocol version mismatch from " + reqAddr + ". Expected " +
                                std::to_string(Utils::protocolVersion()) + ", got " + std::to_string(clientProtoVer) + ".");
                    disconnect();
                    return;
                }

                Utils::log("Client protocol version " + std::to_string(clientProtoVer) + " accepted from " + reqAddr + ".");

                PublicKey signPk;
                std::memcpy(signPk.data(), data.data() + 1, std::min(data.size() - 1, sizeof(signPk)));

                // We can safely store this without further checking, the client will need to send the encrypted AES key in a way where they must possess the corresponding private key anyways.
                int r = crypto_sign_ed25519_pk_to_curve25519(mConnectionPublicKey.data(), signPk.data()); // Store the client's public encryption key key (for identification)
                if (r != 0) {
                    Utils::error("Conversion of client signing key to encryption key failed! Killing connection from " + reqAddr);
                    disconnect();

                    return;
                }

                Utils::debug("Client " + reqAddr + " converted public encryption key: " + Utils::bytesToHexString(mConnectionPublicKey.data(), 32));
                
                Utils::debug("Key attempted connect: " + Utils::bytesToHexString(signPk.data(), signPk.size()));

                std::vector<std::string> whitelistedKeys = Utils::getWhitelistedKeys();

                if (std::find(whitelistedKeys.begin(), whitelistedKeys.end(), Utils::bytesToHexString(signPk.data(), signPk.size())) == whitelistedKeys.end()) {
                    Utils::warn("Non-whitelisted client attempted to connect, terminating. Client IP: " + reqAddr);
                    disconnect();

                    return;
                }

                Utils::debug("Client " + reqAddr + " passed authorized_keys");

                mHandler->sendMessage(ServerMessageType::HANDSHAKE_IDENTIFY, Utils::uint8ArrayToString(mLibSodiumWrapper->getPublicKey(), crypto_sign_PUBLICKEYBYTES)); // This public key should always exist
                break;
            }
            case ClientMessageType::HANDSHAKE_CHALLENGE: {
                Utils::log("Received HANDSHAKE_CHALLENGE from " + reqAddr);
                
                // Convert to byte array
                uint8_t challengeData[32];
                std::memcpy(challengeData, data.data(), std::min(data.size(), sizeof(challengeData)));

                // Sign the challenge
                Signature sig = Utils::LibSodiumWrapper::signMessage(
                    challengeData, sizeof(challengeData),
                    mLibSodiumWrapper->getPrivateKey()
                );

                mHandler->sendMessage(ServerMessageType::HANDSHAKE_CHALLENGE_RESPONSE, Utils::uint8ArrayToString(sig.data(), sig.size())); // Placeholder response
                break;   
            }
            case ClientMessageType::HANDSHAKE_EXCHANGE_KEY: {
                Utils::log("Received HANDSHAKE_EXCHANGE_KEY from " + reqAddr);
                
                // Extract encrypted AES key and nonce (nonce is the first 24 bytes, rest is the ciphertext)
                if (data.size() < 24) { // Minimum size check (nonce)
                    Utils::warn("HANDSHAKE_EXCHANGE_KEY from " + reqAddr + " is too short.");
                    disconnect();
                    return;
                }

                AsymNonce nonce{};
                std::memcpy(nonce.data(), data.data(), nonce.size());
                std::vector<uint8_t> ciphertext(data.size() - nonce.size());
                std::memcpy(ciphertext.data(), data.data() + nonce.size(), ciphertext.size());
                try {
                    std::array<uint8_t, 32> arrayPrivateKey;
                    std::copy(mLibSodiumWrapper->getXPrivateKey(),
                              mLibSodiumWrapper->getXPrivateKey() + 32,
                              arrayPrivateKey.begin());

                    // Decrypt the AES key using the client's public key and server's private key
                    std::vector<uint8_t> decrypted = Utils::LibSodiumWrapper::decryptAsymmetric(
                        ciphertext.data(), ciphertext.size(),
                        nonce,
                        mConnectionPublicKey,
                        arrayPrivateKey
                    );

                    if (decrypted.size() != 32) {
                        Utils::warn("Decrypted HANDSHAKE_EXCHANGE_KEY from " + reqAddr + " has invalid size.");
                        disconnect();
                        return;
                    }

                    std::memcpy(mConnectionAESKey.data(), decrypted.data(), decrypted.size());

                    // Make a Session ID
                    randombytes_buf(&mConnectionSessionID, sizeof(mConnectionSessionID));

                    // Encrypt the Session ID with the established AES key (using symmetric encryption, nonce can be all zeros for this purpose)
                    Nonce symNonce{}; // All zeros

                    std::string networkString = mRawServerConfig->find("NETWORK")->second; // The load check guarantees that this value exists
                    uint8_t configMask = std::stoi(mRawServerConfig->find("SUBNET_MASK")->second); // Same deal here

                    uint32_t baseIP = Net::VirtualInterface::stringToIpv4(networkString);

                    if (baseIP == 0) {
                        Utils::warn("Your NETWORK value in the server configuration is malformed! I will not be able to accept connections! (Connection " + reqAddr + " was killed)");
                        disconnect();
                        return;
                    }

                    uint32_t clientIP = SessionRegistry::getInstance().getFirstAvailableIP(baseIP, configMask);

                    if (clientIP == 0) {
                        Utils::warn("Out of available IPs! Disconnecting client " + reqAddr);
                        disconnect();
                        return;
                    }

                    Protocol::TunConfig tunConfig{};
                    tunConfig.version = Utils::protocolVersion();
                    tunConfig.prefixLength = 24;
                    tunConfig.mtu = 1420;
                    tunConfig.serverIP = htonl(baseIP + 1); // e.g. 10.10.0.1
                    tunConfig.clientIP = htonl(clientIP); // e.g. 10.10.0.X
                    tunConfig.dns1 = htonl(0x08080808);    // 8.8.8.8
                    tunConfig.dns2 = 0;
                    
                    SessionRegistry::getInstance().lockIP(mConnectionSessionID, clientIP);

                    uint64_t sessionIDNet = Utils::chtobe64(mConnectionSessionID);

                    std::vector<uint8_t> payload(sizeof(uint64_t) + sizeof(tunConfig));
                    std::memcpy(payload.data(), &sessionIDNet, sizeof(uint64_t));
                    std::memcpy(payload.data() + sizeof(uint64_t), &tunConfig, sizeof(tunConfig));

                    std::vector<uint8_t> encryptedPayload = Utils::LibSodiumWrapper::encryptMessage(
                        payload.data(), payload.size(),
                        mConnectionAESKey, symNonce
                    );

                    mHandler->sendMessage(ServerMessageType::HANDSHAKE_EXCHANGE_KEY_CONFIRM, Utils::uint8ArrayToString(encryptedPayload.data(), encryptedPayload.size()));

                    // Add to session registry
                    Utils::log("Handshake with " + reqAddr + " completed successfully. Session ID assigned (" + std::to_string(mConnectionSessionID) + ").");
                    auto session = std::make_shared<SessionState>(mConnectionAESKey, std::chrono::hours(12), clientIP, htonl(0x0A0A0001), mConnectionSessionID);
                    SessionRegistry::getInstance().put(mConnectionSessionID, std::move(session));

                } catch (const std::exception& e) {
                    Utils::error("Failed to decrypt HANDSHAKE_EXCHANGE_KEY from " + reqAddr + ": " + e.what());
                    disconnect();
                }

                break;
            }
            case ClientMessageType::HEARTBEAT: {
                Utils::debug("Received HEARTBEAT from " + reqAddr);
                mHandler->sendMessage(ServerMessageType::HEARTBEAT_ACK, ""); // Send ACK
                break;
            }
            case ClientMessageType::HEARTBEAT_ACK: {
                Utils::debug("Received HEARTBEAT_ACK from " + reqAddr);
                mLastHeartbeatReceived = std::chrono::steady_clock::now();
                mMissedHeartbeats = 0; // Reset missed heartbeat count
                break;
            }
            case ClientMessageType::GRACEFUL_DISCONNECT: {
                Utils::log("Received GRACEFUL_DISCONNECT from " + reqAddr + ": " + data);
                disconnect();
                break;
            }
            default:
                Utils::warn("Unhandled message type from " + reqAddr);
                break;
        }
    }
}