// client_session.cpp - Client Session data for ColumnLynx
// Copyright (C) 2026 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#include <columnlynx/client/client_session.hpp>

namespace ColumnLynx {
    std::shared_ptr<ClientState> ClientSession::getClientState() const {
        std::shared_lock lock(mMutex);
        return mClientState;
    }

    void ClientSession::setClientState(std::shared_ptr<ClientState> state) {
        std::unique_lock lock(mMutex);
        mClientState = state;
    }

    const std::shared_ptr<Utils::LibSodiumWrapper>& ClientSession::getSodiumWrapper() const {
        return getClientState()->sodiumWrapper;
    }

    const SymmetricKey& ClientSession::getAESKey() const {
        return getClientState()->aesKey;
    }

    bool ClientSession::isInsecureMode() const {
        return getClientState()->insecureMode;
    }

    const std::string& ClientSession::getConfigPath() const {
        return getClientState()->configPath;
    }

    const std::shared_ptr<Net::VirtualInterface>& ClientSession::getVirtualInterface() const {
        return getClientState()->virtualInterface;
    }

    uint64_t ClientSession::getSessionID() const {
        return getClientState()->sessionID;
    }

    void ClientSession::setSodiumWrapper(std::shared_ptr<Utils::LibSodiumWrapper> sodiumWrapper) {
        std::unique_lock lock(mMutex);
        mClientState->sodiumWrapper = sodiumWrapper;
    }

    void ClientSession::setAESKey(const SymmetricKey& aesKey) {
        std::unique_lock lock(mMutex);
        mClientState->aesKey = aesKey;
    }

    void ClientSession::setInsecureMode(bool insecureMode) {
        std::unique_lock lock(mMutex);
        mClientState->insecureMode = insecureMode;
    }

    void ClientSession::setConfigPath(const std::string& configPath) {
        std::unique_lock lock(mMutex);
        mClientState->configPath = configPath;
    }

    void ClientSession::setVirtualInterface(std::shared_ptr<Net::VirtualInterface> virtualInterface) {
        std::unique_lock lock(mMutex);
        mClientState->virtualInterface = virtualInterface;
    }

    void ClientSession::setSessionID(uint64_t sessionID) {
        std::unique_lock lock(mMutex);
        mClientState->sessionID = sessionID;
    }
}