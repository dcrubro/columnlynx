// tcp_message_type.hpp - TCP Message Types for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the GPLv3 license. See LICENSE for details.

#pragma once

#include <cstdint>
#include <variant>

namespace ColumnLynx::Net::TCP {
    enum class ServerMessageType : uint8_t { // Server to Client
        HANDSHAKE_IDENTIFY  = 0x02, // Send server identity (public key, server name, etc)
        HANDSHAKE_CHALLENGE_RESPONSE = 0x04, // Response to client's challenge
        HANDSHAKE_EXCHANGE_KEY_CONFIRM = 0x06, // If accepted, send encrypted AES key and session ID

        // Shared
        HEARTBEAT = 0xF0, // Keep-alive message
        HEARTBEAT_ACK = 0xF1, // Acknowledgement of keep-alive
        GRACEFUL_DISCONNECT = 0xFE, // Notify client of impending disconnection
        KILL_CONNECTION    = 0xFF, // Forecefully terminate the connection (with cleanup if possible), reserved for unrecoverable errors
    };

    enum class ClientMessageType : uint8_t { // Client to Server
        HANDSHAKE_INIT      = 0xA1, // Request connection
        HANDSHAKE_CHALLENGE = 0xA3, // Challenge ownership of private key
        HANDSHAKE_EXCHANGE_KEY   = 0xA5, // Accept or reject identity, can kill the connection, also sends the AES key

        // Shared
        HEARTBEAT = 0xF0, // Keep-alive message
        HEARTBEAT_ACK = 0xF1, // Acknowledgement of keep-alive
        GRACEFUL_DISCONNECT = 0xFE, // Notify server of impending disconnection
        KILL_CONNECTION    = 0xFF, // Forecefully terminate the connection (with cleanup if possible), reserved for unrecoverable errors
    };

    // Make a variant type for either message type
    using AnyMessageType = std::variant<ServerMessageType, ClientMessageType>;
}