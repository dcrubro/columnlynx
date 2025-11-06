// utils.cpp - Utility functions for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the GPLv3 license. See LICENSE for details.

#include <columnlynx/common/utils.hpp>

namespace ColumnLynx::Utils {
    void log(const std::string &msg) {
        std::cout << "[LOG] " << msg << std::endl;
    }

    void warn(const std::string &msg) {
        std::cerr << "[WARN] " << msg << std::endl;
    }

    void error(const std::string &msg) {
        std::cerr << "[ERROR] " << msg << std::endl;
    }

    std::string getHostname() {
#ifdef _WIN32
        char hostname[256];
        DWORD size = sizeof(hostname);
        if (GetComputerNameA(hostname, &size)) {
            return std::string(hostname);
        } else {
            return "UnknownHost";
        }
#else
        char hostname[256];
        if (gethostname(hostname, sizeof(hostname)) == 0) {
            return std::string(hostname);
        } else {
            return "UnknownHost";
        }
#endif
    }

    std::string getVersion() {
        return "a0.1";
    }

    unsigned short serverPort() {
        return 48042;
    }
}