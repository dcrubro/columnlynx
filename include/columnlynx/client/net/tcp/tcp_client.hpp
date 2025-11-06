// tcp_client.hpp - TCP Client for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the GPLv3 license. See LICENSE for details.

#pragma once

#include <asio/asio.hpp>
#include <columnlynx/common/net/tcp/tcp_message_handler.hpp>
#include <columnlynx/common/net/tcp/tcp_message_type.hpp>
#include <columnlynx/common/net/tcp/net_helper.hpp>
#include <columnlynx/common/utils.hpp>

using asio::ip::tcp;

namespace ColumnLynx::Net::TCP {
    class TCPClient : public std::enable_shared_from_this<TCPClient> {
        public:
            TCPClient(asio::io_context& ioContext,
                      const std::string& host,
                      const std::string& port)
                : mResolver(ioContext), mSocket(ioContext), mHost(host), mPort(port) {}

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
                                        mHandler->sendMessage(ClientMessageType::HANDSHAKE_INIT, "Hello, I am " + Utils::getHostname());
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

        private:
            void mHandleMessage(ServerMessageType type, const std::string& data) {
                switch (type) {
                    case ServerMessageType::HANDSHAKE_IDENTIFY:
                        Utils::log("Received server identity: " + data);
                        //std::memcpy(mServerPublicKey, data.data(), std::min(data.size(), sizeof(mServerPublicKey)));
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
            tcp::resolver mResolver;
            tcp::socket mSocket;
            std::shared_ptr<MessageHandler> mHandler;
            std::string mHost, mPort;
            uint8_t mServerPublicKey[32]; // Assuming 256-bit public key
    };
}