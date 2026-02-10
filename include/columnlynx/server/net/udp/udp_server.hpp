// udp_server.hpp - UDP Server for ColumnLynx
// Copyright (C) 2026 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#pragma once

#include <asio.hpp>
#include <columnlynx/common/net/udp/udp_message_type.hpp>
#include <columnlynx/common/utils.hpp>
#include <array>
#include <columnlynx/common/net/virtual_interface.hpp>
#include <columnlynx/common/libsodium_wrapper.hpp>
#include <columnlynx/server/server_session.hpp>

namespace ColumnLynx::Net::UDP {
    class UDPServer {
        public:
            UDPServer(asio::io_context& ioContext, uint16_t port)
                : mSocket(ioContext)
            {
                asio::error_code ec_open, ec_v6only, ec_bind;

                if (!mIpv4Only) {
                    asio::ip::udp::endpoint endpoint_v6(asio::ip::udp::v6(), port);
                
                    // Try opening IPv6 socket
                    mSocket.open(endpoint_v6.protocol(), ec_open);
                
                    if (!ec_open) {
                        // Try enabling dual-stack (non fatal if it fails)
                        mSocket.set_option(asio::ip::v6_only(false), ec_v6only);
                    
                        // Attempt bind
                        mSocket.bind(endpoint_v6, ec_bind);
                    }
                }

                // Fallback to IPv4 if IPv6 is unusable
                if (mIpv4Only || ec_open || ec_bind) {
                    if (!mIpv4Only) {
                        Utils::warn(
                            "UDP: IPv6 unavailable (open=" + ec_open.message() +
                            ", bind=" + ec_bind.message() +
                            "), falling back to IPv4 only"
                        );
                    }
                
                    asio::ip::udp::endpoint endpoint_v4(asio::ip::udp::v4(), port);
                
                    mSocket.close();
                    mSocket = asio::ip::udp::socket(ioContext); // fully reset internal state
                    mSocket.open(endpoint_v4.protocol());
                    mSocket.bind(endpoint_v4);
                }

                Utils::log("Started UDP server on port " + std::to_string(port));
                mStartReceive();
            }

            // Stop the UDP server
            void stop();

            // Send UDP data to an endpoint; Fetched via the Session Registry
            void sendData(uint32_t sessionID, const std::string& data);

        private:
            // Start receiving UDP data
            void mStartReceive();
            // Handle an incoming UDP packet
            void mHandlePacket(std::size_t bytes);

            asio::ip::udp::socket mSocket;
            asio::ip::udp::endpoint mRemoteEndpoint;
            std::array<uint8_t, 2048> mRecvBuffer; // 2048 seems stable
            bool mIpv4Only = ServerSession::getInstance().isIPv4Only();
            const std::shared_ptr<VirtualInterface> mTun = ServerSession::getInstance().getVirtualInterface();
    };
}