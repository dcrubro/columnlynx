// tcp_client.hpp - TCP Client for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the GPLv3 license. See LICENSE for details.

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

using asio::ip::tcp;

namespace ColumnLynx::Net::TCP {
    class TCPClient : public std::enable_shared_from_this<TCPClient> {
        public:
            TCPClient(asio::io_context& ioContext,
                      const std::string& host,
                      const std::string& port,
                      Utils::LibSodiumWrapper* sodiumWrapper,
                      std::array<uint8_t, 32>* aesKey,
                      uint64_t* sessionIDRef)
                : mResolver(ioContext), mSocket(ioContext), mHost(host), mPort(port), mLibSodiumWrapper(sodiumWrapper), mGlobalKeyRef(aesKey), mSessionIDRef(sessionIDRef) {}

            void start() {
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
                                        mHandler->sendMessage(ClientMessageType::HANDSHAKE_INIT, Utils::uint8ArrayToString(mLibSodiumWrapper->getXPublicKey(), crypto_box_PUBLICKEYBYTES));
                                    } else {
                                        Utils::error("Client connect failed: " + ec.message());
                                    }
                                });
                        } else {
                            Utils::error("Client resolve failed: " + ec.message());
                        }
                    });
            }

            void sendMessage(ClientMessageType type, const std::string& data = "") {
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

            void disconnect() {
                if (mConnected && mHandler) {
                    mHandler->sendMessage(ClientMessageType::GRACEFUL_DISCONNECT, "Goodbye");

                    asio::error_code ec;

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

            bool isHandshakeComplete() const {
                return mHandshakeComplete;
            }

        private:
            void mHandleMessage(ServerMessageType type, const std::string& data) {
                switch (type) {
                    case ServerMessageType::HANDSHAKE_IDENTIFY:
                        Utils::log("Received server identity: " + data);
                        std::memcpy(mServerPublicKey, data.data(), std::min(data.size(), sizeof(mServerPublicKey)));

                        // Generate and send challenge
                        {
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

                            if (decrypted.size() != sizeof(mConnectionSessionID)) {
                                Utils::error("Decrypted session ID has invalid size. Terminating connection.");
                                disconnect();
                                return;
                            }

                            std::memcpy(&mConnectionSessionID, decrypted.data(), sizeof(mConnectionSessionID));
                            Utils::log("Connection established with Session ID: " + std::to_string(mConnectionSessionID));
                        
                            if (mSessionIDRef) { // Copy to the global reference
                                *mSessionIDRef = mConnectionSessionID;
                            }

                            mHandshakeComplete = true;
                        }
                    
                        break;
                    case ServerMessageType::GRACEFUL_DISCONNECT:
                        Utils::log("Server is disconnecting: " + data);
                        if (mConnected) { // Prevent Recursion
                            disconnect();
                        }
                        break;
                    default:
                        Utils::log("Received unknown message type from server.");
                        break;
                }
            }

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
    };
}