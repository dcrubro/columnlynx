// utils.hpp - Utility functions for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#pragma once
#include <iostream>
#include <string>
#include <cstdint>
#include <array>

#ifdef _WIN32
    #include <winsock2.h>
    #include <windows.h>
#else
    #include <sys/utsname.h>
    #include <unistd.h>
#endif

namespace ColumnLynx::Utils {
    void log(const std::string &msg);
    void warn(const std::string &msg);
    void error(const std::string &msg);

    std::string getHostname();
    std::string getVersion();
    unsigned short serverPort();
    unsigned char protocolVersion();

    // Raw byte to hex string conversion helper
    std::string bytesToHexString(const uint8_t* bytes, size_t length);

    // uint8_t to raw string conversion helper
    template <size_t N>
    inline std::string uint8ArrayToString(const std::array<uint8_t, N>& arr) {
        return std::string(reinterpret_cast<const char*>(arr.data()), N);
    }

    inline std::string uint8ArrayToString(const uint8_t* data, size_t length) {
        return std::string(reinterpret_cast<const char*>(data), length);
    }
};