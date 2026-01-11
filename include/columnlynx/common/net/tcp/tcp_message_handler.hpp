// tcp_message_handler.hpp - TCP Message Handler for ColumnLynx
// Copyright (C) 2026 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <functional>
#include <asio.hpp>
#include <columnlynx/common/net/tcp/tcp_message_type.hpp>
#include <columnlynx/common/utils.hpp>

namespace ColumnLynx::Net::TCP {
    class MessageHandler : public std::enable_shared_from_this<MessageHandler> {
        public:
            MessageHandler(asio::ip::tcp::socket socket)
                : mSocket(std::move(socket)) {}
            
            asio::ip::tcp::socket &socket() { return mSocket; }

            void start();
            void sendMessage(AnyMessageType type, const std::string &payload = "");
            void onMessage(std::function<void(AnyMessageType, std::string)> callback);
            void onDisconnect(std::function<void(const asio::error_code&)> callback) {
                mOnDisconnect = std::move(callback);
            }
        
            static AnyMessageType decodeMessageType(uint8_t code);
            static uint8_t toUint8(const AnyMessageType& type);

        private:
            void mReadHeader();
            void mReadBody(uint16_t length);

            asio::ip::tcp::socket mSocket;
            AnyMessageType mCurrentType = ServerMessageType::KILL_CONNECTION; // Doesn't matter initial value
            std::array<uint8_t, 3> mHeader{}; // [type][lenHigh][lenLow]
            std::vector<uint8_t> mBody;
            std::function<void(AnyMessageType, std::string)> mOnMessage;
            std::function<void(asio::error_code&)> mOnDisconnect;
    };
}