// udp_server.hpp - UDP Server for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#pragma once

#include <asio/asio.hpp>
#include <columnlynx/common/net/udp/udp_message_type.hpp>
#include <columnlynx/common/utils.hpp>
#include <array>
#include <columnlynx/common/net/virtual_interface.hpp>

namespace ColumnLynx::Net::UDP {
    class UDPServer {
        public:
            UDPServer(asio::io_context& ioContext, uint16_t port, bool* hostRunning, bool ipv4Only = false, std::shared_ptr<VirtualInterface> tun = nullptr)
                : mSocket(ioContext), mHostRunning(hostRunning), mTun(tun)
            {
                asio::error_code ec;

                if (!ipv4Only) {
                    // Try IPv6 first (dual-stack check)
                    asio::ip::udp::endpoint endpoint_v6(asio::ip::udp::v6(), port);
                    mSocket.open(endpoint_v6.protocol(), ec);
                    if (!ec) {
                        mSocket.set_option(asio::ip::v6_only(false), ec); // Allow dual-stack if possible
                        mSocket.bind(endpoint_v6, ec);
                    }
                }

                // Fallback to IPv4 if anything failed
                if (ec || ipv4Only) {
                    Utils::warn("UDP: IPv6 unavailable (" + ec.message() + "), falling back to IPv4 only");

                    asio::ip::udp::endpoint endpoint_v4(asio::ip::udp::v4(), port);
                    mSocket.close(); // ensure clean state
                    mSocket.open(endpoint_v4.protocol());
                    mSocket.bind(endpoint_v4);
                }

                Utils::log("Started UDP server on port " + std::to_string(port));
                mStartReceive();
            }

            // Stop the UDP server
            void stop();

            // Send UDP data to an endpoint; Fetched via the Session Registry
            void sendData(const uint64_t sessionID, const std::string& data);

        private:
            // Start receiving UDP data
            void mStartReceive();
            // Handle an incoming UDP packet
            void mHandlePacket(std::size_t bytes);

            asio::ip::udp::socket mSocket;
            asio::ip::udp::endpoint mRemoteEndpoint;
            std::array<uint8_t, 2048> mRecvBuffer; // Adjust size as needed
            bool* mHostRunning;
            std::shared_ptr<VirtualInterface> mTun;
    };
}