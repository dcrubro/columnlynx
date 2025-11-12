// udp_server.cpp - UDP Server for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#include <columnlynx/server/net/udp/udp_server.hpp>
#include <columnlynx/common/libsodium_wrapper.hpp>
#include <columnlynx/common/net/session_registry.hpp>
#include <sodium.h>
#include <memory>

namespace ColumnLynx::Net::UDP {
    void UDPServer::mStartReceive() {
        mSocket.async_receive_from(
            asio::buffer(mRecvBuffer), mRemoteEndpoint,
            [this](asio::error_code ec, std::size_t bytes) {
                if (ec) {
                    if (ec == asio::error::operation_aborted) return; // Socket closed
                    // Other recv error
                    if (mHostRunning && *mHostRunning) mStartReceive();
                    return;
                }
                if (bytes > 0) mHandlePacket(bytes);
                if (mHostRunning && *mHostRunning) mStartReceive();
            }
        );
    }

    void UDPServer::mHandlePacket(std::size_t bytes) {
        if (bytes < sizeof(UDPPacketHeader))
            return;
        
        const auto* hdr = reinterpret_cast<UDPPacketHeader*>(mRecvBuffer.data());

        // Get plaintext session ID (assuming first 8 bytes after nonce (header))
        uint64_t sessionID = 0;
        std::memcpy(&sessionID, mRecvBuffer.data() + sizeof(UDPPacketHeader), sizeof(uint64_t));

        auto it = mRecvBuffer.begin() + sizeof(UDPPacketHeader) + sizeof(uint64_t);
        std::vector<uint8_t> encryptedPayload(it, mRecvBuffer.begin() + bytes);

        // Get associated session state
        std::shared_ptr<const SessionState> session = SessionRegistry::getInstance().get(sessionID);

        if (!session) {
            Utils::warn("UDP: Unknown or invalid session from " + mRemoteEndpoint.address().to_string());
            return;
        }

        // Decrypt the actual payload
        try {
            auto plaintext = Utils::LibSodiumWrapper::decryptMessage(
                encryptedPayload.data(), encryptedPayload.size(),
                session->aesKey,
                hdr->nonce,
                "udp-data"
            );

            const_cast<SessionState*>(session.get())->setUDPEndpoint(mRemoteEndpoint); // Update endpoint after confirming decryption
            // Update recv counter
            const_cast<SessionState*>(session.get())->recv_ctr.fetch_add(1, std::memory_order_relaxed);

            // For now, just log the decrypted payload
            std::string payloadStr(plaintext.begin(), plaintext.end());
            Utils::log("UDP: Received packet from " + mRemoteEndpoint.address().to_string() + " - Payload: " + payloadStr);

            // TODO: Process the packet payload, for now just echo back
            mSendData(sessionID, std::string(plaintext.begin(), plaintext.end()));
        } catch (...) {
            Utils::warn("UDP: Failed to decrypt payload from " + mRemoteEndpoint.address().to_string());
            return;
        }
    }

    void UDPServer::mSendData(const uint64_t sessionID, const std::string& data) {
        // Find the IPv4/IPv6 endpoint for the session
        std::shared_ptr<const SessionState> session = SessionRegistry::getInstance().get(sessionID);
        if (!session) {
            Utils::warn("UDP: Cannot send data, unknown session ID " + std::to_string(sessionID));
            return;
        }

        asio::ip::udp::endpoint endpoint = session->udpEndpoint;
        if (endpoint.address().is_unspecified()) {
            Utils::warn("UDP: Cannot send data, session ID " + std::to_string(sessionID) + " has no known UDP endpoint.");
            return;
        }

        // Prepare packet
        UDPPacketHeader hdr{};
        randombytes_buf(hdr.nonce.data(), hdr.nonce.size());

        auto encryptedPayload = Utils::LibSodiumWrapper::encryptMessage(
            reinterpret_cast<const uint8_t*>(data.data()), data.size(),
            session->aesKey, hdr.nonce, "udp-data"
        );

        std::vector<uint8_t> packet;
        packet.reserve(sizeof(UDPPacketHeader) +  sizeof(uint64_t) + encryptedPayload.size());
        packet.insert(packet.end(), 
            reinterpret_cast<uint8_t*>(&hdr),
            reinterpret_cast<uint8_t*>(&hdr) + sizeof(UDPPacketHeader)
        );
        packet.insert(packet.end(),
            reinterpret_cast<const uint8_t*>(&sessionID),
            reinterpret_cast<const uint8_t*>(&sessionID) + sizeof(sessionID)
        );
        packet.insert(packet.end(), encryptedPayload.begin(), encryptedPayload.end());

        // Send packet
        mSocket.send_to(asio::buffer(packet), endpoint);
        Utils::log("UDP: Sent packet of size " + std::to_string(packet.size()) + " to " + std::to_string(sessionID) + " (" + endpoint.address().to_string() + ":" + std::to_string(endpoint.port()) + ")");
    }

    void UDPServer::stop() {
        if (mSocket.is_open()) {
            asio::error_code ec;
            mSocket.cancel(ec);
            mSocket.close(ec);
            Utils::log("UDP Socket closed.");
        }
    }
}