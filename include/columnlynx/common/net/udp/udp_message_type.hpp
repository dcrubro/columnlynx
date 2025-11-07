// udp_message_type.hpp - UDP Message Types for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the GPLv3 license. See LICENSE for details.

#pragma once

#include <cstdint>
#include <variant>
#include <array>

namespace ColumnLynx::Net::UDP {
    // Shared between server and client
    enum class MessageType : uint8_t {
        PING = 0x01,
        PONG = 0x02,
        DATA = 0x03
    };

    struct UDPPacketHeader {
        std::array<uint8_t, 12> nonce;
    };

    /*enum class ServerMessageType : uint8_t { // Server to Client
        
    };

    enum class ClientMessageType : uint8_t { // Client to Server

    };

    // Make a variant type for either message type
    using AnyMessageType = std::variant<ServerMessageType, ClientMessageType>;*/
}