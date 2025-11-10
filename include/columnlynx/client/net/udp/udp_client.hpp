// udp_client.hpp - UDP Client for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#pragma once

#include <asio/asio.hpp>
#include <columnlynx/common/net/udp/udp_message_type.hpp>
#include <columnlynx/common/utils.hpp>
#include <columnlynx/common/libsodium_wrapper.hpp>
#include <array>

namespace ColumnLynx::Net::UDP {
    class UDPClient {
        public:
            UDPClient(asio::io_context& ioContext,
                      const std::string& host,
                      const std::string& port,
                      std::array<uint8_t, 32>* aesKeyRef,
                      uint64_t* sessionIDRef)
                : mSocket(ioContext), mResolver(ioContext), mHost(host), mPort(port), mAesKeyRef(aesKeyRef), mSessionIDRef(sessionIDRef) { mStartReceive(); }

            void start() {
                auto endpoints = mResolver.resolve(asio::ip::udp::v4(), mHost, mPort);
                mRemoteEndpoint = *endpoints.begin();
                mSocket.open(asio::ip::udp::v4());
                Utils::log("UDP Client ready to send to " + mRemoteEndpoint.address().to_string() + ":" + std::to_string(mRemoteEndpoint.port()));
            }

            void sendMessage(const std::string& data = "") {
                UDPPacketHeader hdr{};
                randombytes_buf(hdr.nonce.data(), hdr.nonce.size());

                if (mAesKeyRef == nullptr || mSessionIDRef == nullptr) {
                    Utils::error("UDP Client AES key or Session ID reference is null!");
                    return;
                }

                auto encryptedPayload = Utils::LibSodiumWrapper::encryptMessage(
                    reinterpret_cast<const uint8_t*>(data.data()), data.size(),
                    *mAesKeyRef, hdr.nonce, "udp-data"
                );

                std::vector<uint8_t> packet;
                packet.reserve(sizeof(UDPPacketHeader) + sizeof(uint64_t) + encryptedPayload.size());
                packet.insert(packet.end(), 
                    reinterpret_cast<uint8_t*>(&hdr),
                    reinterpret_cast<uint8_t*>(&hdr) + sizeof(UDPPacketHeader)
                );
                uint64_t sid = *mSessionIDRef;
                packet.insert(packet.end(),
                    reinterpret_cast<uint8_t*>(&sid),
                    reinterpret_cast<uint8_t*>(&sid) + sizeof(sid)
                );
                packet.insert(packet.end(), encryptedPayload.begin(), encryptedPayload.end());

                mSocket.send_to(asio::buffer(packet), mRemoteEndpoint);
                Utils::log("Sent UDP packet of size " + std::to_string(packet.size()));
            }

            void stop() {
                if (mSocket.is_open()) {
                    asio::error_code ec;
                    mSocket.cancel(ec);
                    mSocket.close(ec);
                    Utils::log("UDP Client socket closed.");
                }
            }

        private:
            void mStartReceive() {
                mSocket.async_receive_from(
                    asio::buffer(mRecvBuffer), mRemoteEndpoint,
                    [this](asio::error_code ec, std::size_t bytes) {
                        if (ec) {
                            if (ec == asio::error::operation_aborted) return; // Socket closed
                            // Other recv error
                            mStartReceive();
                            return;
                        }

                        if (bytes > 0) {
                            mHandlePacket(bytes);
                        }

                        mStartReceive();
                    }
                );
            }

            void mHandlePacket(std::size_t bytes) {
                if (bytes < sizeof(UDPPacketHeader) + sizeof(uint64_t)) {
                    Utils::warn("UDP Client received packet too small to process.");
                    return;
                }

                // Parse header
                UDPPacketHeader hdr;
                std::memcpy(&hdr, mRecvBuffer.data(), sizeof(UDPPacketHeader));

                // Parse session ID
                uint64_t sessionID;
                std::memcpy(&sessionID, mRecvBuffer.data() + sizeof(UDPPacketHeader), sizeof(uint64_t));

                // Decrypt payload
                std::vector<uint8_t> ciphertext(
                    mRecvBuffer.begin() + sizeof(UDPPacketHeader) + sizeof(uint64_t),
                    mRecvBuffer.begin() + bytes
                );

                if (mAesKeyRef == nullptr) {
                    Utils::error("UDP Client AES key reference is null!");
                    return;
                }

                std::vector<uint8_t> plaintext = Utils::LibSodiumWrapper::decryptMessage(
                    ciphertext.data(), ciphertext.size(), *mAesKeyRef, hdr.nonce, "udp-data"
                );

                if (plaintext.empty()) {
                    Utils::warn("UDP Client failed to decrypt received packet.");
                    return;
                }

                Utils::log("UDP Client received packet from " + mRemoteEndpoint.address().to_string() + " - Packet size: " + std::to_string(bytes));
            }

            asio::ip::udp::socket mSocket;
            asio::ip::udp::resolver mResolver;
            asio::ip::udp::endpoint mRemoteEndpoint;
            std::string mHost;
            std::string mPort;
            std::array<uint8_t, 32>* mAesKeyRef;
            uint64_t* mSessionIDRef;
            std::array<uint8_t, 2048> mRecvBuffer; // Adjust size as needed
    };
}