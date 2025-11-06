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
};