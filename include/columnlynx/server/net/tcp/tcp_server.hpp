// tcp_server.hpp - TCP Server for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>
#include <memory>
#include <unordered_set>
#include <new>
#include <asio/asio.hpp>
#include <columnlynx/common/net/tcp/tcp_message_type.hpp>
#include <columnlynx/common/utils.hpp>
#include <columnlynx/server/net/tcp/tcp_connection.hpp>
#include <columnlynx/common/libsodium_wrapper.hpp>
#include <columnlynx/common/net/protocol_structs.hpp>

namespace ColumnLynx::Net::TCP {

    class TCPServer {
        public:
            TCPServer(asio::io_context& ioContext,
                      uint16_t port,
                      Utils::LibSodiumWrapper* sodiumWrapper,
                      bool* hostRunning, bool ipv4Only = false)
                : mIoContext(ioContext),
                  mAcceptor(ioContext),
                  mSodiumWrapper(sodiumWrapper),
                  mHostRunning(hostRunning)
            {
                asio::error_code ec;
            
                if (!ipv4Only) {
                    // Try IPv6 first (dual-stack check)
                    asio::ip::tcp::endpoint endpoint_v6(asio::ip::tcp::v6(), port);
                    mAcceptor.open(endpoint_v6.protocol(), ec);
                    if (!ec) {
                        mAcceptor.set_option(asio::ip::v6_only(false), ec); // Allow dual-stack if possible
                        mAcceptor.bind(endpoint_v6, ec);
                    }
                }
            
                // Fallback to IPv4 if anything failed
                if (ec || ipv4Only) {
                    Utils::warn("TCP: IPv6 unavailable (" + ec.message() + "), falling back to IPv4 only");
                
                    asio::ip::tcp::endpoint endpoint_v4(asio::ip::tcp::v4(), port);
                    mAcceptor.close(); // ensure clean state
                    mAcceptor.open(endpoint_v4.protocol());
                    mAcceptor.bind(endpoint_v4);
                }
            
                // Start listening
                mAcceptor.listen();
                Utils::log("Started TCP server on port " + std::to_string(port));
                mStartAccept();
            }

            void stop();

        private:
            void mStartAccept();
            asio::io_context &mIoContext;
            asio::ip::tcp::acceptor mAcceptor;
            std::unordered_set<TCPConnection::pointer> mClients;
            Utils::LibSodiumWrapper *mSodiumWrapper;
            bool* mHostRunning;
    };

}