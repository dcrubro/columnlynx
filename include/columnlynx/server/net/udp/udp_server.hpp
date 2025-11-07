// udp_server.hpp - UDP Server for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the GPLv3 license. See LICENSE for details.

#pragma once

#include <asio/asio.hpp>
#include <columnlynx/common/net/udp/udp_message_type.hpp>
#include <columnlynx/common/utils.hpp>
#include <array>

namespace ColumnLynx::Net::UDP {
    class UDPServer {
        public:
            UDPServer(asio::io_context& ioContext, uint16_t port)
                : mSocket(ioContext, asio::ip::udp::endpoint(asio::ip::udp::v4(), port))
            {
                Utils::log("Started UDP server on port " + std::to_string(port));
                mStartReceive();
            }

        private:
            void mStartReceive();
            void mHandlePacket(std::size_t bytes);
            void mSendData(const uint64_t sessionID, const std::string& data);
            asio::ip::udp::socket mSocket;
            asio::ip::udp::endpoint mRemoteEndpoint;
            std::array<uint8_t, 2048> mRecvBuffer; // Adjust size as needed
    };
}