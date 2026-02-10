// session_registry.cpp - Session Registry for ColumnLynx
// Copyright (C) 2026 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#include <columnlynx/common/net/session_registry.hpp>

namespace ColumnLynx::Net {
    void SessionRegistry::put(uint32_t sessionID, std::shared_ptr<SessionState> state) {
        std::unique_lock lock(mMutex);
        mSessions[sessionID] = std::move(state);
        mIPSessions[mSessions[sessionID]->clientTunIP] = mSessions[sessionID];
    }

    std::shared_ptr<const SessionState> SessionRegistry::get(uint32_t sessionID) const {
        std::shared_lock lock(mMutex);
        auto it = mSessions.find(sessionID);
        return (it == mSessions.end()) ? nullptr : it->second;
    }

    std::shared_ptr<const SessionState> SessionRegistry::getByIP(uint32_t ip) const {
        std::shared_lock lock(mMutex);
        auto it = mIPSessions.find(ip);
        return (it == mIPSessions.end()) ? nullptr : it->second;
    }

    std::unordered_map<uint32_t, std::shared_ptr<SessionState>> SessionRegistry::snapshot() const {
        std::unordered_map<uint32_t, std::shared_ptr<SessionState>> snap;
        std::shared_lock lock(mMutex);
        snap = mSessions;
        return snap;
    }

    void SessionRegistry::erase(uint32_t sessionID) {
        std::unique_lock lock(mMutex);
        mSessions.erase(sessionID);
    }

    void SessionRegistry::cleanupExpired() {
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

    int SessionRegistry::size() const {
        std::shared_lock lock(mMutex);
        return static_cast<int>(mSessions.size());
    }

    uint32_t SessionRegistry::getFirstAvailableIP(uint32_t baseIP, uint8_t mask) const {
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

    void SessionRegistry::lockIP(uint32_t sessionID, uint32_t ip) {
        std::unique_lock lock(mMutex);
        mSessionIPs[sessionID] = ip;
        
        /*if (mIPSessions.find(sessionID) == mIPSessions.end()) {
            Utils::debug("yikes");
        }*/
        mIPSessions[ip] = mSessions.find(sessionID)->second;
    }

    void SessionRegistry::deallocIP(uint32_t sessionID) {
        std::unique_lock lock(mMutex);
    
        auto it = mSessionIPs.find(sessionID);
        if (it != mSessionIPs.end()) {
            uint32_t ip = it->second;
            mIPSessions.erase(ip);
            mSessionIPs.erase(it);
        }
    }
}