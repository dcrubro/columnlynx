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
        uint64_t sessionID;

        ~ClientState() { sodium_memzero(aesKey.data(), aesKey.size()); }
        ClientState(const ClientState&) = delete;
        ClientState& operator=(const ClientState&) = delete;
        ClientState(ClientState&&) = default;
        ClientState& operator=(ClientState&&) = default;

        explicit ClientState() = default;

        explicit ClientState(std::shared_ptr<Utils::LibSodiumWrapper> sodium, SymmetricKey& k, bool insecure,
                             std::string& config, std::shared_ptr<Net::VirtualInterface> tun, uint64_t session)
        : sodiumWrapper(sodium), aesKey(k), insecureMode(insecure), configPath(config), virtualInterface(tun), sessionID(session) {}
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
            uint64_t getSessionID() const;

            // Setters
            void setSodiumWrapper(std::shared_ptr<Utils::LibSodiumWrapper> sodiumWrapper);
            void setAESKey(const SymmetricKey& aesKey);
            void setInsecureMode(bool insecureMode);
            void setConfigPath(const std::string& configPath);
            void setVirtualInterface(std::shared_ptr<Net::VirtualInterface> virtualInterface);
            void setSessionID(uint64_t sessionID);

        private:
            mutable std::shared_mutex mMutex;
            std::shared_ptr<struct ClientState> mClientState{nullptr};
    };
}