// session_registry.hpp - Session Registry for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#pragma once
#include <unordered_set>
#include <shared_mutex>
#include <memory>
#include <chrono>
#include <array>
#include <sodium.h>
#include <columnlynx/common/utils.hpp>
#include <columnlynx/common/libsodium_wrapper.hpp>

namespace ColumnLynx::Net {
    struct SessionState {
        SymmetricKey aesKey; // Immutable after creation
        std::atomic<uint64_t> send_ctr{0}; // Per-direction counters
        std::atomic<uint64_t> recv_ctr{0};
        asio::ip::udp::endpoint udpEndpoint;
        std::atomic<uint64_t> sendCounter{0};
        std::chrono::steady_clock::time_point created = std::chrono::steady_clock::now();
        std::chrono::steady_clock::time_point expires{};
        uint32_t clientTunIP;
        uint32_t serverTunIP;
        uint64_t sessionID;
        Nonce base_nonce{};

        ~SessionState() { sodium_memzero(aesKey.data(), aesKey.size()); }
        SessionState(const SessionState&) = delete;
        SessionState& operator=(const SessionState&) = delete;
        SessionState(SessionState&&) = default;
        SessionState& operator=(SessionState&&) = default;

        explicit SessionState(const SymmetricKey& k, std::chrono::seconds ttl = std::chrono::hours(24), uint32_t clientIP = 0, uint32_t serverIP = 0, uint64_t id = 0) : aesKey(k), clientTunIP(clientIP), serverTunIP(serverIP), sessionID(id) {
            expires = created + ttl;
        }

        void setUDPEndpoint(const asio::ip::udp::endpoint& ep) {
            udpEndpoint = ep;
        }
    };

    class SessionRegistry {
        public:
            static SessionRegistry& getInstance() { static SessionRegistry instance; return instance; }

            // Insert or replace
            void put(uint64_t sessionID, std::shared_ptr<SessionState> state) {
                std::unique_lock lock(mMutex);
                mSessions[sessionID] = std::move(state);
                mIPSessions[mSessions[sessionID]->clientTunIP] = mSessions[sessionID];
            }

            // Lookup
            std::shared_ptr<const SessionState> get(uint64_t sessionID) const {
                std::shared_lock lock(mMutex);
                auto it = mSessions.find(sessionID);
                return (it == mSessions.end()) ? nullptr : it->second;
            }

            std::shared_ptr<const SessionState> getByIP(uint32_t ip) const {
                std::shared_lock lock(mMutex);
                auto it = mIPSessions.find(ip);
                return (it == mIPSessions.end()) ? nullptr : it->second;
            }

            std::unordered_map<uint64_t, std::shared_ptr<SessionState>> snapshot() const {
                std::unordered_map<uint64_t, std::shared_ptr<SessionState>> snap;
                std::shared_lock lock(mMutex);
                snap = mSessions;
                return snap;
            }

            // Remove
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

            int size() const {
                std::shared_lock lock(mMutex);
                return static_cast<int>(mSessions.size());
            }

            // IP management (simple for /24 subnet)

            uint32_t getFirstAvailableIP() const {
                std::shared_lock lock(mMutex);
                uint32_t baseIP = 0x0A0A0002; // 10.10.0.2

                // TODO: Expand to support larger subnets
                for (uint32_t offset = 0; offset < 254; offset++) {
                    uint32_t candidateIP = baseIP + offset;
                    if (mSessionIPs.find(candidateIP) == mSessionIPs.end()) {
                        return candidateIP;
                    }                    
                }
            }

            void lockIP(uint64_t sessionID, uint32_t ip) {
                std::unique_lock lock(mMutex);
                mSessionIPs[sessionID] = ip;
            }

            void deallocIP(uint64_t sessionID) {
                std::unique_lock lock(mMutex);
                mSessionIPs.erase(sessionID);
            }

        private:
            mutable std::shared_mutex mMutex;
            std::unordered_map<uint64_t, std::shared_ptr<SessionState>> mSessions;
            std::unordered_map<uint64_t, uint32_t> mSessionIPs;
            std::unordered_map<uint32_t, std::shared_ptr<SessionState>> mIPSessions;
    };
}