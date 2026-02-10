// client_session.hpp - Client Session data for ColumnLynx
// Copyright (C) 2026 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#pragma once

#include <memory>
#include <columnlynx/common/libsodium_wrapper.hpp>
#include <array>
#include <columnlynx/common/net/virtual_interface.hpp>
#include <shared_mutex>

namespace ColumnLynx {
    struct ClientState {
        std::shared_ptr<Utils::LibSodiumWrapper> sodiumWrapper;
        SymmetricKey aesKey;
        bool insecureMode;
        std::string configPath;
        std::shared_ptr<Net::VirtualInterface> virtualInterface;
        uint32_t sessionID;
        uint64_t recv_cnt;
        uint64_t send_cnt;
        uint32_t noncePrefix;

        ~ClientState() { sodium_memzero(aesKey.data(), aesKey.size()); }
        ClientState(const ClientState&) = delete;
        ClientState& operator=(const ClientState&) = delete;
        ClientState(ClientState&&) = default;
        ClientState& operator=(ClientState&&) = default;

        explicit ClientState() = default;

        explicit ClientState(std::shared_ptr<Utils::LibSodiumWrapper> sodium, SymmetricKey& k, bool insecure,
                     std::string& config, std::shared_ptr<Net::VirtualInterface> tun, uint32_t session, uint64_t recv, uint64_t send)
        : sodiumWrapper(sodium), aesKey(k), insecureMode(insecure), configPath(config), virtualInterface(tun), sessionID(session), recv_cnt(recv), send_cnt(send) {}
    };
    
    class ClientSession {
        public:
            // Return a reference to the Client Session instance
            static ClientSession& getInstance() { static ClientSession instance; return instance; }

            // Return the current client state
            std::shared_ptr<ClientState> getClientState() const;

            // Set the client state
            void setClientState(std::shared_ptr<ClientState> state);

            // Get the wrapper for libsodium
            const std::shared_ptr<Utils::LibSodiumWrapper>& getSodiumWrapper() const;
            // Get the AES key
            const SymmetricKey& getAESKey() const;
            // Get whether insecure mode is enabled
            bool isInsecureMode() const;
            // Get the config path
            const std::string& getConfigPath() const;
            // Get the virtual interface
            const std::shared_ptr<Net::VirtualInterface>& getVirtualInterface() const;
            // Get the session ID
            uint32_t getSessionID() const;
            uint64_t getRecvCount() const {
                std::shared_lock lock(mMutex);
                return mClientState->recv_cnt;
            }

            uint64_t getSendCount() const {
                std::shared_lock lock(mMutex);
                return mClientState->send_cnt;
            }

            uint32_t getNoncePrefix() const {
                std::shared_lock lock(mMutex);
                return mClientState->noncePrefix;
            }

            // Setters
            void setSodiumWrapper(std::shared_ptr<Utils::LibSodiumWrapper> sodiumWrapper);
            void setAESKey(const SymmetricKey& aesKey);
            void setInsecureMode(bool insecureMode);
            void setConfigPath(const std::string& configPath);
            void setVirtualInterface(std::shared_ptr<Net::VirtualInterface> virtualInterface);
            void setSessionID(uint32_t sessionID);
            void incrementRecvCount() {
                std::unique_lock lock(mMutex);
                mClientState->recv_cnt++;
            }

            void incrementSendCount() {
                std::unique_lock lock(mMutex);
                mClientState->send_cnt++;
            }

            void setNoncePrefix(uint32_t prefix) {
                std::unique_lock lock(mMutex);
                mClientState->noncePrefix = prefix;
            }

        private:
            mutable std::shared_mutex mMutex;
            std::shared_ptr<struct ClientState> mClientState{nullptr};
    };
}