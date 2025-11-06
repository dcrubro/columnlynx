// tcp_connection.hpp - TCP Connection for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the GPLv3 license. See LICENSE for details.

#pragma once

#include <iostream>
#include <memory>
#include <string>
#include <ctime>
#include <cstdint>
#include <asio/asio.hpp>
#include <columnlynx/common/net/tcp/tcp_message_type.hpp>
#include <columnlynx/common/net/tcp/tcp_message_handler.hpp>
#include <columnlynx/common/utils.hpp>
#include <columnlynx/common/libsodium_wrapper.hpp>

namespace ColumnLynx::Net::TCP {
    class TCPConnection : public std::enable_shared_from_this<TCPConnection> {
        public:
            using pointer = std::shared_ptr<TCPConnection>;

            static pointer create(
                asio::ip::tcp::socket socket,
                Utils::LibSodiumWrapper *libsodium,
                std::function<void(pointer)> onDisconnect)
            {
                auto conn = pointer(new TCPConnection(std::move(socket), libsodium));
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
        
        private:
            TCPConnection(asio::ip::tcp::socket socket, Utils::LibSodiumWrapper *libsodium)
                : mHandler(std::make_shared<MessageHandler>(std::move(socket))), mLibSodiumWrapper(libsodium) {}

            void mHandleMessage(ClientMessageType type, const std::string& data) {
                std::string reqAddr = mHandler->socket().remote_endpoint().address().to_string();
            
                switch (type) {
                    case ClientMessageType::HANDSHAKE_INIT: {
                        Utils::log("Received HANDSHAKE_INIT from " + reqAddr + ": " + data);
                        mHandler->sendMessage(ServerMessageType::HANDSHAKE_IDENTIFY, std::string(reinterpret_cast<const char*>(mLibSodiumWrapper->getPublicKey())));
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
    };
}