// protocol_structs.hpp - Network Protocol Structures
// Copyright (C) 2025 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#pragma once

#include <cstdint>

namespace ColumnLynx::Protocol {
    #pragma pack(push, 1)
    struct TunConfig {
        uint8_t version;
        uint8_t prefixLength;
        uint16_t mtu;
        uint32_t serverIP;
        uint32_t clientIP;
        uint32_t dns1;
        uint32_t dns2;
    };
    #pragma pack(pop)
}