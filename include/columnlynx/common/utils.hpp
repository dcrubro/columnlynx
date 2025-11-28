// utils.hpp - Utility functions for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#pragma once
#include <iostream>
#include <string>
#include <cstdint>
#include <array>
#include <iomanip>
#include <sstream>
#include <vector>
#include <fstream>
#include <chrono>
#include <unordered_map>

#ifdef _WIN32
    #include <winsock2.h>
    #include <windows.h>
#else
    #include <sys/utsname.h>
    #include <unistd.h>
#endif

namespace ColumnLynx::Utils {
    // General log function. Use for logging important information.
    void log(const std::string &msg);
    // General warning function. Use for logging important warnings.
    void warn(const std::string &msg);
    // General error function. Use for logging failures and general errors.
    void error(const std::string &msg);
    // Debug log function. Use for logging non-important information. These will not print unless the binary is compiled with DEBUG=1
    void debug(const std::string &msg);

    // Returns the hostname of the running platform.
    std::string getHostname();
    // Returns the version of the running release.
    std::string getVersion();
    unsigned short serverPort();
    unsigned char protocolVersion();
    std::vector<std::string> getWhitelistedKeys();

    // Raw byte to hex string conversion helper
    std::string bytesToHexString(const uint8_t* bytes, size_t length);
    // Hex string to raw byte conversion helper
    std::vector<uint8_t> hexStringToBytes(const std::string& hex);

    // uint8_t to raw string conversion helper
    template <size_t N>
    inline std::string uint8ArrayToString(const std::array<uint8_t, N>& arr) {
        return std::string(reinterpret_cast<const char*>(arr.data()), N);
    }

    inline std::string uint8ArrayToString(const uint8_t* data, size_t length) {
        return std::string(reinterpret_cast<const char*>(data), length);
    }

    inline constexpr uint64_t cbswap64(uint64_t x) {
        return ((x & 0x00000000000000FFULL) << 56) |
               ((x & 0x000000000000FF00ULL) << 40) |
               ((x & 0x0000000000FF0000ULL) << 24) |
               ((x & 0x00000000FF000000ULL) << 8)  |
               ((x & 0x000000FF00000000ULL) >> 8)  |
               ((x & 0x0000FF0000000000ULL) >> 24) |
               ((x & 0x00FF000000000000ULL) >> 40) |
               ((x & 0xFF00000000000000ULL) >> 56);
    }

    // host -> big-endian (for little-endian hosts) - 64 bit
    inline constexpr uint64_t chtobe64(uint64_t x) {
        return cbswap64(x);
    }

    // big-endian -> host (for little-endian hosts) - 64 bit
    inline constexpr uint64_t cbe64toh(uint64_t x) {
        return cbswap64(x);
    }

    // Returns the config file in an unordered_map format. This purely reads the config file, you still need to parse it manually.
    std::unordered_map<std::string, std::string> getConfigMap(std::string path);
};