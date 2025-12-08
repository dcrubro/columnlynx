// session_registry.hpp - Session Registry for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#pragma once
#include <unordered_set>
#include <shared_mutex>
#include <memory>
#include <chrono>
#include <array>
#include <cmath>
#include <sodium.h>
#include <mutex>
#include <atomic>
#include <asio.hpp>
#include <columnlynx/common/utils.hpp>
#include <columnlynx/common/libsodium_wrapper.hpp>

namespace ColumnLynx::Net {
    struct SessionState {
        SymmetricKey aesKey; // Agreed-upon AES-256 kes for that session; Immutable after creation
        std::atomic<uint64_t> send_ctr{0}; // Per-direction counters
        std::atomic<uint64_t> recv_ctr{0}; // Per-direction counters
        asio::ip::udp::endpoint udpEndpoint; // Deducted IP + Port of that session client
        std::atomic<uint64_t> sendCounter{0}; // Counter of sent messages
        std::chrono::steady_clock::time_point created = std::chrono::steady_clock::now(); // Time created
        std::chrono::steady_clock::time_point expires{}; // Time of expiry
        uint32_t clientTunIP; // Assigned IP
        uint32_t serverTunIP; // Server IP
        uint64_t sessionID; // Session ID
        Nonce base_nonce{};

        ~SessionState() { sodium_memzero(aesKey.data(), aesKey.size()); }
        SessionState(const SessionState&) = delete;
        SessionState& operator=(const SessionState&) = delete;
        SessionState(SessionState&&) = default;
        SessionState& operator=(SessionState&&) = default;

        explicit SessionState(const SymmetricKey& k, std::chrono::seconds ttl = std::chrono::hours(24), uint32_t clientIP = 0, uint32_t serverIP = 0, uint64_t id = 0) : aesKey(k), clientTunIP(clientIP), serverTunIP(serverIP), sessionID(id) {
            expires = created + ttl;
        }

        // Set the UDP endpoint
        void setUDPEndpoint(const asio::ip::udp::endpoint& ep) {
            udpEndpoint = ep;
        }
    };

    class SessionRegistry {
        public:
            // Return a reference to the Session Registry instance
            static SessionRegistry& getInstance() { static SessionRegistry instance; return instance; }

            // Insert or replace a session entry
            void put(uint64_t sessionID, std::shared_ptr<SessionState> state);

            // Lookup a session entry by session ID
            std::shared_ptr<const SessionState> get(uint64_t sessionID) const;

            // Lookup a session entry by IPv4
            std::shared_ptr<const SessionState> getByIP(uint32_t ip) const;

            // Get a snapshot of the Session Registry
            std::unordered_map<uint64_t, std::shared_ptr<SessionState>> snapshot() const;

            // Remove a session by ID
            void erase(uint64_t sessionID);

            // Cleanup expired sessions
            void cleanupExpired();

            // Get the number of registered sessions
            int size() const;

            // IP management

            // Get the lowest available IPv4 address; Returns 0 if none available
            uint32_t getFirstAvailableIP(uint32_t baseIP, uint8_t mask) const;

            // Lock IP to session ID; Do NOT call before put() - You will segfault!
            void lockIP(uint64_t sessionID, uint32_t ip);

            // Unlock IP from session ID
            void deallocIP(uint64_t sessionID);

        private:
            mutable std::shared_mutex mMutex;
            std::unordered_map<uint64_t, std::shared_ptr<SessionState>> mSessions;
            std::unordered_map<uint64_t, uint32_t> mSessionIPs;
            std::unordered_map<uint32_t, std::shared_ptr<SessionState>> mIPSessions;
    };
}