// utils.cpp - Utility functions for ColumnLynx
// Copyright (C) 2026 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#include <columnlynx/common/utils.hpp>

namespace ColumnLynx::Utils {
    std::string unixMillisToISO8601(uint64_t unixMillis, bool local) {
        using namespace std::chrono;

        // Convert milliseconds since epoch to system_clock::time_point
        system_clock::time_point tp = system_clock::time_point(milliseconds(unixMillis));

        // Convert to time_t for localtime conversion
        std::time_t tt = system_clock::to_time_t(tp);
        std::tm localTm;

        if (local) {
#ifdef _WIN32
        localtime_s(&localTm, &tt);
#else
        localtime_r(&tt, &localTm);
#endif
        } else {
#ifdef _WIN32
        gmtime_s(&localTm, &tt);
#else
        gmtime_r(&tt, &localTm);
#endif
        }

        // Format the time to ISO 8601
        char buffer[30];
        std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", &localTm);

        // Append milliseconds
        auto ms = duration_cast<milliseconds>(tp.time_since_epoch()) % 1000;
        char iso8601[34];
        std::snprintf(iso8601, sizeof(iso8601), "%s.%03lld", buffer, static_cast<long long>(ms.count()));

        return std::string(iso8601);
    }

    void log(const std::string &msg) {
        uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        std::cout << "\033[0m[" << unixMillisToISO8601(now) << " LOG] " << msg << std::endl;
    }

    void warn(const std::string &msg) {
        uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        std::cerr << "\033[33m[" << unixMillisToISO8601(now) << " WARN] " << msg << "\033[0m" << std::endl;
    }

    void error(const std::string &msg) {
        uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        std::cerr << "\033[31m[" << unixMillisToISO8601(now) << " ERROR] " << msg << "\033[0m" << std::endl;
    }

    void debug(const std::string &msg) {
#if DEBUG || _DEBUG
        uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        std::cerr << "\033[95m[" << unixMillisToISO8601(now) << " DEBUG] " << msg << "\033[0m" << std::endl;
#else
        return;
#endif
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
        return "1.1.0";
    }

    unsigned short serverPort() {
        return 48042;
    }

    unsigned char protocolVersion() {
        return 1;
    }

    std::string bytesToHexString(const uint8_t* bytes, size_t length) {
        const char hexChars[] = "0123456789ABCDEF";
        std::string hexString;
        hexString.reserve(length * 2);

        for (size_t i = 0; i < length; ++i) {
            uint8_t byte = bytes[i];
            hexString.push_back(hexChars[(byte >> 4) & 0x0F]);
            hexString.push_back(hexChars[byte & 0x0F]);
        }

        return hexString;
    }

    std::vector<uint8_t> hexStringToBytes(const std::string& hex) {
        // TODO: recover from errors

        if (hex.length() % 2 != 0) {
            throw std::invalid_argument("Hex string must have even length");
        }
    
        auto hexValue = [](char c) -> uint8_t {
            if ('0' <= c && c <= '9') return c - '0';
            if ('A' <= c && c <= 'F') return c - 'A' + 10;
            if ('a' <= c && c <= 'f') return c - 'a' + 10;
            throw std::invalid_argument("Invalid hex character");
        };
    
        size_t len = hex.length();
        std::vector<uint8_t> bytes;
        bytes.reserve(len / 2);
    
        for (size_t i = 0; i < len; i += 2) {
            uint8_t high = hexValue(hex[i]);
            uint8_t low  = hexValue(hex[i + 1]);
            bytes.push_back((high << 4) | low);
        }
    
        return bytes;
    }

    std::vector<std::string> getWhitelistedKeys(std::string basePath) {
        // Currently re-reads the file every time, should be fine.
        // Advantage of it is that you don't need to reload the server binary after adding/removing keys. Disadvantage is re-reading the file every time.
        // I might redo this part.

        std::vector<std::string> out;

        std::ifstream file(basePath + "whitelisted_keys");
        if (!file.is_open()) {
            warn("Failed to open whitelisted_keys file at path: " + basePath + "whitelisted_keys");
            return out;
        }

        std::string line;
        while (std::getline(file, line)) {
            // Convert to upper case to align with the bytesToHexString() output
            for (int i = 0; i < line.length(); i++) {
                line[i] = toupper(line[i]);
            }
            out.push_back(line);
        }

        return out;
    }

    std::unordered_map<std::string, std::string> getConfigMap(std::string path, std::vector<std::string> requiredKeys) {
        // TODO: Currently re-reads every time.
        std::vector<std::string> readLines;

        std::ifstream file(path);
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open config file at path: " + path);
        }

        std::string line;

        while (std::getline(file, line)) {
            readLines.push_back(line);
        }

        // Parse them into the struct
        std::unordered_map<std::string, std::string> config;
        char delimiter = '=';

        for (std::string &str : readLines) {
            std::stringstream ss(str);

            std::string key;
            std::string val;

            std::getline(ss, key, delimiter);
            std::getline(ss, val, delimiter);

            config.insert({ key, val });
        }

        if (!requiredKeys.empty()) {
            for (std::string x : requiredKeys) {
                if (config.find(x) == config.end()) {
                    throw std::runtime_error("Config doesn't contain all required keys! (Missing: '" + x + "')");
                }
            }
        }

        return config;
    }
}