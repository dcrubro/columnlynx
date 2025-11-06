// utils.hpp - Utility functions for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the GPLv3 license. See LICENSE for details.

#pragma once
#include <iostream>
#include <string>

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