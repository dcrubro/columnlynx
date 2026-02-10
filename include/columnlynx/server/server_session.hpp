// server_session.hpp - Client Session data for ColumnLynx
// Copyright (C) 2026 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#pragma once

#include <memory>
#include <columnlynx/common/libsodium_wrapper.hpp>
#include <array>
#include <columnlynx/common/net/virtual_interface.hpp>
#include <shared_mutex>

namespace ColumnLynx {
    struct ServerState {
        std::shared_ptr<Utils::LibSodiumWrapper> sodiumWrapper;
        std::shared_ptr<Net::VirtualInterface> virtualInterface;
        std::string configPath;
        std::unordered_map<std::string, std::string> serverConfig;
        bool ipv4Only;
        bool hostRunning;

        ~ServerState() = default;
        ServerState(const ServerState&) = delete;
        ServerState& operator=(const ServerState&) = delete;
        ServerState(ServerState&&) = default;
        ServerState& operator=(ServerState&&) = default;

        explicit ServerState() = default;
    };
    
    class ServerSession {
        public:
            // Return a reference to the Server Session instance
            static ServerSession& getInstance() { static ServerSession instance; return instance; }

            // Return the current server state
            std::shared_ptr<ServerState> getServerState() const;

            // Set the server state
            void setServerState(std::shared_ptr<ServerState> state);

            // Getters
            std::shared_ptr<Utils::LibSodiumWrapper> getSodiumWrapper() const;
            const std::string& getConfigPath() const;
            const std::unordered_map<std::string, std::string>& getRawServerConfig() const;
            const std::shared_ptr<Net::VirtualInterface>& getVirtualInterface() const;
            bool isIPv4Only() const;
            bool isHostRunning() const;

            // Setters
            void setSodiumWrapper(std::shared_ptr<Utils::LibSodiumWrapper> sodiumWrapper);
            void setConfigPath(const std::string& configPath);
            void setRawServerConfig(const std::unordered_map<std::string, std::string>& config);
            void setVirtualInterface(std::shared_ptr<Net::VirtualInterface> tun);
            void setIPv4Only(bool ipv4Only);
            void setHostRunning(bool hostRunning);

        private:
            mutable std::shared_mutex mMutex;
            std::shared_ptr<struct ServerState> mServerState{nullptr};
    };
}