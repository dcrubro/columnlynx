// udp_server.cpp - UDP Server for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the GPLv3 license. See LICENSE for details.

#include <columnlynx/server/net/udp/udp_server.hpp>
#include <columnlynx/common/libsodium_wrapper.hpp>
#include <columnlynx/common/net/session_registry.hpp>
#include <sodium.h>
#include <memory>

namespace ColumnLynx::Net::UDP {
    void UDPServer::mStartReceive() {
        // A bit of a shotty implementation, might improve later
        /*if (mHostRunning != nullptr && !(*mHostRunning)) {
            Utils::log("Server is stopping, not receiving new packets.");
            return;
        }*/

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

            // TODO: Process the packet payload

            // For now, just log the decrypted payload
            std::string payloadStr(plaintext.begin(), plaintext.end());
            Utils::log("UDP: Received packet from " + mRemoteEndpoint.address().to_string() + " - Payload: " + payloadStr);
        } catch (...) {
            Utils::warn("UDP: Failed to decrypt payload from " + mRemoteEndpoint.address().to_string());
            return;
        }
    }

    void UDPServer::mSendData(const uint64_t sessionID, const std::string& data) {
        // TODO: Implement
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