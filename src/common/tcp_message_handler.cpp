// tcp_message_handler.cpp - TCP Message Handler for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#include <columnlynx/common/net/tcp/tcp_message_handler.hpp>
#include <columnlynx/common/net/tcp/net_helper.hpp>
#include <columnlynx/common/utils.hpp>

namespace ColumnLynx::Net::TCP {
    void MessageHandler::start() {
        mReadHeader();
    }
    void MessageHandler::sendMessage(AnyMessageType type, const std::string &payload) {
        // Type is a variant between ServerMessageType and ClientMessageType
        // Convert to uint8_t dynamically
        uint8_t typeByte = std::visit([](auto type) -> uint8_t {
            return static_cast<uint8_t>(type);
        }, type);

        std::vector<uint8_t> data;
        data.push_back(typeByte);
        uint16_t length = payload.size();

        data.push_back(length >> 8);
        data.push_back(length & 0xFF);

        data.insert(data.end(), payload.begin(), payload.end());
        auto self = shared_from_this();
        asio::async_write(mSocket, asio::buffer(data),
            [self](asio::error_code ec, std::size_t) {
                if (ec) {
                    Utils::error("Send failed: " + ec.message());
                }
            }
        );
    }
    
    void MessageHandler::onMessage(std::function<void(AnyMessageType, std::string)> callback) {
        mOnMessage = std::move(callback);
    }

    void MessageHandler::mReadHeader() {
        auto self = shared_from_this();
        asio::async_read(mSocket, asio::buffer(mHeader),
            [this, self](asio::error_code ec, std::size_t) {
                if (!NetHelper::isExpectedDisconnect(ec)) {
                    mCurrentType = decodeMessageType(mHeader[0]);

                    uint16_t len = (mHeader[1] << 8) | mHeader[2];
                    mReadBody(len);
                } else {
                    Utils::error("Header read failed: " + ec.message());
                }
            }
        );
    }

    void MessageHandler::mReadBody(uint16_t length) {
        auto self = shared_from_this();
        mBody.resize(length);

        asio::async_read(mSocket, asio::buffer(mBody),
            [this, self](asio::error_code ec, std::size_t) {
                if (!NetHelper::isExpectedDisconnect(ec)) {
                    std::string payload(mBody.begin(), mBody.end());
                    
                    // Dispatch based on message type
                    if (mOnMessage) {
                        mOnMessage(mCurrentType, payload);
                    }

                    mReadHeader(); // Keep listening
                } else {
                    Utils::error("Body read failed: " + ec.message());

                    if (mOnDisconnect) {
                        mOnDisconnect(ec);
                    }
                }
            }
        );
    }

    AnyMessageType MessageHandler::decodeMessageType(uint8_t code) {
        switch (code) {
            case 0xFE: return ServerMessageType::GRACEFUL_DISCONNECT;
            case 0xFF: return ServerMessageType::KILL_CONNECTION;
            default: break;
        }

        if (code >= 0xA0) {
            return static_cast<ClientMessageType>(code);
        } else {
            return static_cast<ServerMessageType>(code);
        }
    }

    uint8_t MessageHandler::toUint8(const AnyMessageType& type) {
        return std::visit([](auto t) -> uint8_t {
            return static_cast<uint8_t>(t);
        }, type);
    }
}