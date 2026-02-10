// server_session.cpp - Client Session data for ColumnLynx
// Copyright (C) 2026 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#include <columnlynx/server/server_session.hpp>

namespace ColumnLynx {
    std::shared_ptr<ServerState> ServerSession::getServerState() const {
        std::shared_lock lock(mMutex);
        return mServerState;
    }

    void ServerSession::setServerState(std::shared_ptr<ServerState> state) {
        std::unique_lock lock(mMutex);
        mServerState = std::move(state);
    }

    std::shared_ptr<Utils::LibSodiumWrapper> ServerSession::getSodiumWrapper() const {
        std::shared_lock lock(mMutex);
        return mServerState ? mServerState->sodiumWrapper : nullptr;
    }

    const std::string& ServerSession::getConfigPath() const {
        static const std::string emptyString;
        std::shared_ptr<ServerState> state = getServerState();
        return state ? state->configPath : emptyString;
    }

    const std::unordered_map<std::string, std::string>& ServerSession::getRawServerConfig() const {
        static const std::unordered_map<std::string, std::string> emptyMap;
        std::shared_ptr<ServerState> state = getServerState();
        return state ? state->serverConfig : emptyMap;
    }

    const std::shared_ptr<Net::VirtualInterface>& ServerSession::getVirtualInterface() const {
        static const std::shared_ptr<Net::VirtualInterface> nullTun = nullptr;
        std::shared_ptr<ServerState> state = getServerState();
        return state ? state->virtualInterface : nullTun;
    }

    bool ServerSession::isIPv4Only() const {
        std::shared_ptr<ServerState> state = getServerState();
        return state ? state->ipv4Only : false;
    }

    bool ServerSession::isHostRunning() const {
        std::shared_ptr<ServerState> state = getServerState();
        return state ? state->hostRunning : false;
    }

    void ServerSession::setSodiumWrapper(std::shared_ptr<Utils::LibSodiumWrapper> sodiumWrapper) {
        std::unique_lock lock(mMutex);
        if (!mServerState)
            mServerState = std::make_shared<ServerState>();
        mServerState->sodiumWrapper = std::move(sodiumWrapper);
    }

    void ServerSession::setConfigPath(const std::string& configPath) {
        std::unique_lock lock(mMutex);
        if (!mServerState)
            mServerState = std::make_shared<ServerState>();
        mServerState->configPath = configPath;
    }

    void ServerSession::setRawServerConfig(const std::unordered_map<std::string, std::string>& config) {
        std::unique_lock lock(mMutex);
        if (!mServerState)
            mServerState = std::make_shared<ServerState>();
        mServerState->serverConfig = config;
    }

    void ServerSession::setVirtualInterface(std::shared_ptr<Net::VirtualInterface> tun) {
        std::unique_lock lock(mMutex);
        if (!mServerState)
            mServerState = std::make_shared<ServerState>();
        mServerState->virtualInterface = std::move(tun);
    }

    void ServerSession::setIPv4Only(bool ipv4Only) {
        std::unique_lock lock(mMutex);
        if (!mServerState)
            mServerState = std::make_shared<ServerState>();
        mServerState->ipv4Only = ipv4Only;
    }

    void ServerSession::setHostRunning(bool hostRunning) {
        std::unique_lock lock(mMutex);
        if (!mServerState)
            mServerState = std::make_shared<ServerState>();
        mServerState->hostRunning = hostRunning;
    }
}