// udp_server.cpp - UDP Server for ColumnLynx
// Copyright (C) 2026 DcruBro
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
                    if (ServerSession::getInstance().isHostRunning()) mStartReceive();
                    return;
                }
                if (bytes > 0) mHandlePacket(bytes);
                if (ServerSession::getInstance().isHostRunning()) mStartReceive();
            }
        );
    }

    void UDPServer::mHandlePacket(std::size_t bytes) {
        if (bytes < sizeof(UDPPacketHeader) + sizeof(uint32_t))
            return;
        
        const auto* hdr = reinterpret_cast<UDPPacketHeader*>(mRecvBuffer.data());

        // Get plaintext session ID (first 4 bytes after header, in network byte order)
        uint32_t sessionIDNet = 0;
        std::memcpy(&sessionIDNet, mRecvBuffer.data() + sizeof(UDPPacketHeader), sizeof(uint32_t));
        uint32_t sessionID = sessionIDNet; // ntohl(sessionIDNet); --- IGNORE ---

        auto it = mRecvBuffer.begin() + sizeof(UDPPacketHeader) + sizeof(uint32_t);
        std::vector<uint8_t> encryptedPayload(it, mRecvBuffer.begin() + bytes);

        // Get associated session state
        std::shared_ptr<const SessionState> session = SessionRegistry::getInstance().get(sessionID);

        if (!session) {
            Utils::warn("UDP: Unknown or invalid session from " + mRemoteEndpoint.address().to_string());
            return;
        }

        // Decrypt the actual payload
        try {
            //Utils::debug("Using AES key " + Utils::bytesToHexString(session->aesKey.data(), 32));

            auto plaintext = Utils::LibSodiumWrapper::decryptMessage(
                encryptedPayload.data(), encryptedPayload.size(),
                session->aesKey,
                hdr->nonce, "udp-data"
                //std::string(reinterpret_cast<const char*>(&sessionID), sizeof(uint32_t))
            );

            Utils::debug("Passed decryption");

            const_cast<SessionState*>(session.get())->setUDPEndpoint(mRemoteEndpoint); // Update endpoint after confirming decryption
            // Update recv counter
            const_cast<SessionState*>(session.get())->recv_ctr.fetch_add(1, std::memory_order_relaxed);

            // For now, just log the decrypted payload
            std::string payloadStr(plaintext.begin(), plaintext.end());
            Utils::debug("UDP: Received packet from " + mRemoteEndpoint.address().to_string() + " - Payload: " + payloadStr);

            if (mTun) {
                mTun->writePacket(plaintext); // Send to virtual interface
            }
        } catch (const std::exception &ex) {
            Utils::warn("UDP: Failed to process payload from " + mRemoteEndpoint.address().to_string() + " Raw Error: '" + ex.what() + "'");
            return;
        }
    }

    void UDPServer::sendData(uint32_t sessionID, const std::string& data) {
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
        uint8_t nonce[12];
        uint32_t prefix = session->noncePrefix;
        uint64_t sendCount = const_cast<SessionState*>(session.get())->send_ctr.fetch_add(1, std::memory_order_relaxed);
        memcpy(nonce, &prefix, sizeof(uint32_t)); // Prefix nonce
        memcpy(nonce + sizeof(uint32_t), &sendCount, sizeof(uint64_t)); // Use send count as nonce suffix to ensure uniqueness
        std::copy_n(nonce, 12, hdr.nonce.data());

        auto encryptedPayload = Utils::LibSodiumWrapper::encryptMessage(
            reinterpret_cast<const uint8_t*>(data.data()), data.size(),
            session->aesKey, hdr.nonce, "udp-data"
            //std::string(reinterpret_cast<const char*>(&sessionID), sizeof(uint32_t))
        );

        std::vector<uint8_t> packet;
        packet.reserve(sizeof(UDPPacketHeader) + sizeof(uint32_t) + encryptedPayload.size());
        packet.insert(packet.end(), 
            reinterpret_cast<uint8_t*>(&hdr),
            reinterpret_cast<uint8_t*>(&hdr) + sizeof(UDPPacketHeader)
        );
        uint32_t sessionIDNet = htonl(sessionID);
        packet.insert(packet.end(),
            reinterpret_cast<const uint8_t*>(&sessionIDNet),
            reinterpret_cast<const uint8_t*>(&sessionIDNet) + sizeof(sessionIDNet)
        );
        packet.insert(packet.end(), encryptedPayload.begin(), encryptedPayload.end());

        // Send packet
        mSocket.send_to(asio::buffer(packet), endpoint);
        Utils::debug("UDP: Sent packet of size " + std::to_string(packet.size()) + " to " + std::to_string(sessionID) + " (" + endpoint.address().to_string() + ":" + std::to_string(endpoint.port()) + ")");
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