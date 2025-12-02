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
            void put(uint64_t sessionID, std::shared_ptr<SessionState> state) {
                std::unique_lock lock(mMutex);
                mSessions[sessionID] = std::move(state);
                mIPSessions[mSessions[sessionID]->clientTunIP] = mSessions[sessionID];
            }

            // Lookup a session entry by session ID
            std::shared_ptr<const SessionState> get(uint64_t sessionID) const {
                std::shared_lock lock(mMutex);
                auto it = mSessions.find(sessionID);
                return (it == mSessions.end()) ? nullptr : it->second;
            }

            // Lookup a session entry by IPv4
            std::shared_ptr<const SessionState> getByIP(uint32_t ip) const {
                std::shared_lock lock(mMutex);
                auto it = mIPSessions.find(ip);
                return (it == mIPSessions.end()) ? nullptr : it->second;
            }

            // Get a snapshot of the Session Registry
            std::unordered_map<uint64_t, std::shared_ptr<SessionState>> snapshot() const {
                std::unordered_map<uint64_t, std::shared_ptr<SessionState>> snap;
                std::shared_lock lock(mMutex);
                snap = mSessions;
                return snap;
            }

            // Remove a session by ID
            void erase(uint64_t sessionID) {
                std::unique_lock lock(mMutex);
                mSessions.erase(sessionID);
            }

            // Cleanup expired sessions
            void cleanupExpired() {
                std::unique_lock lock(mMutex);
                auto now = std::chrono::steady_clock::now();
                for (auto it = mSessions.begin(); it != mSessions.end(); ) {
                    if (it->second && it->second->expires <= now) {
                        it = mSessions.erase(it);
                    } else {
                        ++it;
                    }
                }

                for (auto it = mIPSessions.begin(); it != mIPSessions.end(); ) {
                    if (it->second && it->second->expires <= now) {
                        it = mIPSessions.erase(it);
                    } else {
                        ++it;
                    }
                }
            }

            // Get the number of registered sessions
            int size() const {
                std::shared_lock lock(mMutex);
                return static_cast<int>(mSessions.size());
            }

            // IP management

            // Get the lowest available IPv4 address; Returns 0 if none available
            uint32_t getFirstAvailableIP(uint32_t baseIP, uint8_t mask) const {
                std::shared_lock lock(mMutex);

                uint32_t hostCount = (1u << (32 - mask));
                uint32_t firstHost = 2;
                uint32_t lastHost  = hostCount - 2;

                for (uint32_t offset = firstHost; offset <= lastHost; offset++) {
                    uint32_t candidateIP = baseIP + offset;
                    if (mIPSessions.find(candidateIP) == mIPSessions.end()) {
                        return candidateIP;
                    }
                }
            
                return 0;
            }

            void lockIP(uint64_t sessionID, uint32_t ip) {
                std::unique_lock lock(mMutex);
                mSessionIPs[sessionID] = ip;
                mIPSessions[ip] = mSessions.find(sessionID)->second;
            }

            void deallocIP(uint64_t sessionID) {
                std::unique_lock lock(mMutex);
            
                auto it = mSessionIPs.find(sessionID);
                if (it != mSessionIPs.end()) {
                    uint32_t ip = it->second;
                    mIPSessions.erase(ip);
                    mSessionIPs.erase(it);
                }
            }

        private:
            mutable std::shared_mutex mMutex;
            std::unordered_map<uint64_t, std::shared_ptr<SessionState>> mSessions;
            std::unordered_map<uint64_t, uint32_t> mSessionIPs;
            std::unordered_map<uint32_t, std::shared_ptr<SessionState>> mIPSessions;
    };
}