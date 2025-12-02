// udp_client.cpp - UDP Client for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#include <columnlynx/client/net/udp/udp_client.hpp>

namespace ColumnLynx::Net::UDP {
    void UDPClient::start() {
        // TODO: Add IPv6
        auto endpoints = mResolver.resolve(asio::ip::udp::v4(), mHost, mPort);
        mRemoteEndpoint = *endpoints.begin();
        mSocket.open(asio::ip::udp::v4());
        Utils::log("UDP Client ready to send to " + mRemoteEndpoint.address().to_string() + ":" + std::to_string(mRemoteEndpoint.port()));
    }

    void UDPClient::sendMessage(const std::string& data) {
        UDPPacketHeader hdr{};
        randombytes_buf(hdr.nonce.data(), hdr.nonce.size());

        if (mAesKeyRef == nullptr || mSessionIDRef == nullptr) {
            Utils::error("UDP Client AES key or Session ID reference is null!");
            return;
        }

        //Utils::debug("Using AES key: " + Utils::bytesToHexString(mAesKeyRef->data(), 32));

        auto encryptedPayload = Utils::LibSodiumWrapper::encryptMessage(
            reinterpret_cast<const uint8_t*>(data.data()), data.size(),
            *mAesKeyRef, hdr.nonce, "udp-data"
            //std::string(reinterpret_cast<const char*>(&mSessionIDRef), sizeof(uint64_t))
        );

        std::vector<uint8_t> packet;
        packet.reserve(sizeof(UDPPacketHeader) + sizeof(uint64_t) + encryptedPayload.size());
        packet.insert(packet.end(), 
            reinterpret_cast<uint8_t*>(&hdr),
            reinterpret_cast<uint8_t*>(&hdr) + sizeof(UDPPacketHeader)
        );
        packet.insert(packet.end(),
            reinterpret_cast<uint8_t*>(mSessionIDRef.get()),
            reinterpret_cast<uint8_t*>(mSessionIDRef.get()) + sizeof(uint64_t)
        );
        packet.insert(packet.end(), encryptedPayload.begin(), encryptedPayload.end());

        mSocket.send_to(asio::buffer(packet), mRemoteEndpoint);
        Utils::debug("Sent UDP packet of size " + std::to_string(packet.size()));
    }

    void UDPClient::stop() {
        if (mSocket.is_open()) {
            asio::error_code ec;
            mSocket.cancel(ec);
            mSocket.close(ec);
            Utils::log("UDP Client socket closed.");
        }
    }

    void UDPClient::mStartReceive() {
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

    void UDPClient::mHandlePacket(std::size_t bytes) {
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

        if (sessionID != *mSessionIDRef) {
            Utils::warn("Got packet that isn't for me! Dropping!");
            return;
        }

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
            //std::string(reinterpret_cast<const char*>(&mSessionIDRef), sizeof(uint64_t))
        );

        if (plaintext.empty()) {
            Utils::warn("UDP Client failed to decrypt received packet.");
            return;
        }

        Utils::debug("UDP Client received packet from " + mRemoteEndpoint.address().to_string() + " - Packet size: " + std::to_string(bytes));

        // Write to TUN
        if (mTunRef) {
            mTunRef->writePacket(plaintext);
        }
    }
}