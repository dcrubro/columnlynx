// tcp_server.hpp - TCP Server for ColumnLynx
// Copyright (C) 2026 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>
#include <memory>
#include <unordered_set>
#include <new>
#include <asio.hpp>
#include <columnlynx/common/net/tcp/tcp_message_type.hpp>
#include <columnlynx/common/utils.hpp>
#include <columnlynx/server/net/tcp/tcp_connection.hpp>
#include <columnlynx/common/libsodium_wrapper.hpp>
#include <columnlynx/common/net/protocol_structs.hpp>
#include <columnlynx/server/server_session.hpp>

namespace ColumnLynx::Net::TCP {

    class TCPServer {
        public:
            TCPServer(asio::io_context& ioContext,
                      uint16_t port)
                : mIoContext(ioContext),
                  mAcceptor(ioContext)
            {
                // Preload the config map
                asio::error_code ec_open, ec_v6only, ec_bind;

                bool isIPv4Only = ServerSession::getInstance().isIPv4Only();

                if (!isIPv4Only) {
                    // Try IPv6 (dual-stack if supported)
                    asio::ip::tcp::endpoint endpoint_v6(asio::ip::tcp::v6(), port);
                
                    mAcceptor.open(endpoint_v6.protocol(), ec_open);
                
                    if (!ec_open) {
                        // Try enabling dual-stack, but DO NOT treat failure as fatal
                        mAcceptor.set_option(asio::ip::v6_only(false), ec_v6only);
                    
                        // Try binding IPv6
                        mAcceptor.bind(endpoint_v6, ec_bind);
                    }
                }
                
                // If IPv6 bind failed OR IPv6 open failed OR forced IPv4-only
                if (isIPv4Only || ec_open || ec_bind) {
                    if (!isIPv4Only)
                        Utils::warn("TCP: IPv6 unavailable (open=" + ec_open.message() +
                                    ", bind=" + ec_bind.message() +
                                    "), falling back to IPv4 only");
                
                    asio::ip::tcp::endpoint endpoint_v4(asio::ip::tcp::v4(), port);
                
                    mAcceptor.close(); // guarantee clean state
                    mAcceptor.open(endpoint_v4.protocol());
                    mAcceptor.bind(endpoint_v4);
                }
            
                // Start listening
                mAcceptor.listen();
                Utils::log("Started TCP server on port " + std::to_string(port));
                mStartAccept();
            }

            // Stop the TCP Server
            void stop();

        private:
            // Start accepting clients via TCP
            void mStartAccept();
            
            asio::io_context &mIoContext;
            asio::ip::tcp::acceptor mAcceptor;
            std::unordered_set<TCPConnection::pointer> mClients;
    };

}