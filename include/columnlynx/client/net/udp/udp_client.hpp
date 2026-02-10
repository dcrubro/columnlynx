// udp_client.hpp - UDP Client for ColumnLynx
// Copyright (C) 2026 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#pragma once

#include <asio.hpp>
#include <columnlynx/common/net/udp/udp_message_type.hpp>
#include <columnlynx/common/utils.hpp>
#include <columnlynx/common/libsodium_wrapper.hpp>
#include <array>
#include <columnlynx/common/net/virtual_interface.hpp>
#include <columnlynx/client/client_session.hpp>

namespace ColumnLynx::Net::UDP {
    class UDPClient {
        public:
            UDPClient(asio::io_context& ioContext,
                      const std::string& host,
                      const std::string& port)
                : mSocket(ioContext), mResolver(ioContext), mHost(host), mPort(port)
            {
                mStartReceive(); 
            }

            // Start the UDP client
            void start();
            // Send a UDP message
            void sendMessage(const std::string& data = "");
            // Stop the UDP client
            void stop();

        private:
            // Start the UDP listener routine
            void mStartReceive();
            // Handle an incoming UDP message
            void mHandlePacket(std::size_t bytes);

            asio::ip::udp::socket mSocket;
            asio::ip::udp::resolver mResolver;
            asio::ip::udp::endpoint mRemoteEndpoint;
            std::string mHost;
            std::string mPort;
            std::array<uint8_t, 2048> mRecvBuffer; // Adjust size as needed
    };
}