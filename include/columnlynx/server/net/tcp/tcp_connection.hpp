// tcp_connection.hpp - TCP Connection for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the GPLv3 license. See LICENSE for details.

#pragma once

#include <iostream>
#include <memory>
#include <string>
#include <ctime>
#include <cstdint>
#include <new>
#include <asio/asio.hpp>
#include <columnlynx/common/net/tcp/tcp_message_type.hpp>
#include <columnlynx/common/net/tcp/tcp_message_handler.hpp>
#include <columnlynx/common/utils.hpp>
#include <columnlynx/common/libsodium_wrapper.hpp>
#include <columnlynx/common/net/session_registry.hpp>

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

            void start() {
                mHandler->onMessage([this](AnyMessageType type, const std::string& data) {
                    mHandleMessage(static_cast<ClientMessageType>(MessageHandler::toUint8(type)), data);
                });

                mHandler->onDisconnect([this](const asio::error_code& ec) {
                    Utils::log("Client disconnected: " + mHandler->socket().remote_endpoint().address().to_string() + " - " + ec.message());
                    disconnect();
                });

                mHandler->start();

                // Placeholder for message handling setup
                Utils::log("Client connected: " + mHandler->socket().remote_endpoint().address().to_string());
            }
        
            void sendMessage(ServerMessageType type, const std::string& data = "") {
                if (mHandler) {
                    mHandler->sendMessage(type, data);
                }
            }

            void setDisconnectCallback(std::function<void(std::shared_ptr<TCPConnection>)> cb) {
                mOnDisconnect = std::move(cb);
            }

            void disconnect() {
                std::string ip = mHandler->socket().remote_endpoint().address().to_string();

                asio::error_code ec;
                mHandler->socket().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
                mHandler->socket().close(ec);

                Utils::log("Closed connection to " + ip);

                if (mOnDisconnect) {
                    mOnDisconnect(shared_from_this());
                }
            }

            uint64_t getSessionID() const {
                return mConnectionSessionID;
            }

            std::array<uint8_t, 32> getAESKey() const {
                return mConnectionAESKey;
            }
        
        private:
            TCPConnection(asio::ip::tcp::socket socket, Utils::LibSodiumWrapper* sodiumWrapper)
                : mHandler(std::make_shared<MessageHandler>(std::move(socket))), mLibSodiumWrapper(sodiumWrapper) {}

            void mHandleMessage(ClientMessageType type, const std::string& data) {
                std::string reqAddr = mHandler->socket().remote_endpoint().address().to_string();
            
                switch (type) {
                    case ClientMessageType::HANDSHAKE_INIT: {
                        Utils::log("Received HANDSHAKE_INIT from " + reqAddr);
                        std::memcpy(mConnectionPublicKey.data(), data.data(), std::min(data.size(), sizeof(mConnectionPublicKey))); // Store the client's public key (for identification)
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

                            // TODO: Make the session ID little-endian for network transmission

                            // Encrypt the Session ID with the established AES key (using symmetric encryption, nonce can be all zeros for this purpose)
                            Nonce symNonce{}; // All zeros
                            std::vector<uint8_t> encryptedSessionID = Utils::LibSodiumWrapper::encryptMessage(
                                reinterpret_cast<uint8_t*>(&mConnectionSessionID), sizeof(mConnectionSessionID),
                                mConnectionAESKey, symNonce
                            );

                            mHandler->sendMessage(ServerMessageType::HANDSHAKE_EXCHANGE_KEY_CONFIRM, Utils::uint8ArrayToString(encryptedSessionID.data(), encryptedSessionID.size()));

                            // Add to session registry
                            Utils::log("Handshake with " + reqAddr + " completed successfully. Session ID assigned.");
                            auto session = std::make_shared<SessionState>(mConnectionAESKey, std::chrono::hours(12));
                            SessionRegistry::getInstance().put(mConnectionSessionID, std::move(session));

                        } catch (const std::exception& e) {
                            Utils::error("Failed to decrypt HANDSHAKE_EXCHANGE_KEY from " + reqAddr + ": " + e.what());
                            disconnect();
                        }

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

            std::shared_ptr<MessageHandler> mHandler;
            std::function<void(std::shared_ptr<TCPConnection>)> mOnDisconnect;
            Utils::LibSodiumWrapper *mLibSodiumWrapper;
            std::array<uint8_t, 32> mConnectionAESKey;
            uint64_t mConnectionSessionID;
            AsymPublicKey mConnectionPublicKey;
    };
}