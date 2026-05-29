// utils.cpp - Utility functions for ColumnLynx
// Copyright (C) 2026 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#include <columnlynx/common/utils.hpp>
#include <filesystem>
#include <cctype>

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
        return "1.2.0";
    }

    unsigned short serverPort() {
        return 48042;
    }

    unsigned char protocolVersion() {
        return 2;
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

        namespace fs = std::filesystem;
        std::error_code ec;

        fs::path base(basePath);
        fs::path absBase = fs::absolute(base, ec);
        if (ec) {
            warn("getWhitelistedKeys(): failed to resolve base path: " + basePath + " - " + ec.message());
            return out;
        }

        fs::path whitelist = absBase / "whitelisted_keys";
        if (!fs::exists(whitelist, ec) || ec) {
            warn("getWhitelistedKeys(): whitelist file not found: " + whitelist.string());
            return out;
        }

        // Canonicalize to avoid symlink tricks
        fs::path canon = fs::canonical(whitelist, ec);
        if (ec) {
            warn("getWhitelistedKeys(): failed to canonicalize path: " + whitelist.string());
            return out;
        }

        std::ifstream file(canon);
        if (!file.is_open()) {
            warn("getWhitelistedKeys(): failed to open whitelist file: " + canon.string());
            return out;
        }

        std::string line;
        while (std::getline(file, line)) {
            // Trim whitespace
            while (!line.empty() && isspace(static_cast<unsigned char>(line.back()))) line.pop_back();
            size_t start = 0;
            while (start < line.size() && isspace(static_cast<unsigned char>(line[start]))) ++start;
            if (start >= line.size()) continue;
            std::string key = line.substr(start);

            // Convert to upper case to align with the bytesToHexString() output
            for (size_t i = 0; i < key.length(); ++i) {
                key[i] = static_cast<char>(toupper(static_cast<unsigned char>(key[i])));
            }
            out.push_back(key);
        }

        return out;
    }

    std::unordered_map<std::string, std::string> getConfigMap(std::string path, std::vector<std::string> requiredKeys) {
        // TODO: Currently re-reads every time.
        std::vector<std::string> readLines;

        namespace fs = std::filesystem;
        std::error_code ec;
        fs::path p(path);
        fs::path abs = fs::absolute(p, ec);
        if (ec) {
            throw std::runtime_error("getConfigMap(): failed to resolve path: " + path + " - " + ec.message());
        }

        if (!fs::exists(abs, ec) || ec) {
            throw std::runtime_error("getConfigMap(): config file does not exist: " + abs.string());
        }

        fs::path canon = fs::canonical(abs, ec);
        if (ec) {
            throw std::runtime_error("getConfigMap(): failed to canonicalize config path: " + abs.string());
        }

        std::ifstream file(canon);
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open config file at path: " + canon.string());
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

    std::vector<uint8_t> loadHexBytesFromFile(const std::string& path, size_t expectedBytes, const std::string& description, bool warnOnInsecurePermissions) {
        namespace fs = std::filesystem;
        std::error_code ec;

        fs::path p(path);
        fs::path abs = fs::absolute(p, ec);
        if (ec) {
            throw std::runtime_error("loadHexBytesFromFile(): failed to resolve path: " + path + " - " + ec.message());
        }

        if (!fs::exists(abs, ec) || ec) {
            throw std::runtime_error("loadHexBytesFromFile(): file does not exist: " + abs.string());
        }

        fs::path canon = fs::canonical(abs, ec);
        if (ec) {
            throw std::runtime_error("loadHexBytesFromFile(): failed to canonicalize path: " + abs.string());
        }

#ifndef _WIN32
        if (warnOnInsecurePermissions) {
            ec.clear();
            fs::file_status status = fs::status(canon, ec);
            if (ec) {
                warn("loadHexBytesFromFile(): failed to inspect permissions for " + canon.string() + " - " + ec.message());
            } else {
                auto perms = status.permissions();
                if ((perms & (fs::perms::group_all | fs::perms::others_all)) != fs::perms::none) {
                    warn(description + " file permissions are too permissive: " + canon.string() + " (recommend chmod 600)");
                }

                if (!fs::is_regular_file(status)) {
                    warn(description + " path is not a regular file: " + canon.string());
                }
            }
        }
#endif

        std::ifstream file(canon);
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open " + description + " file at path: " + canon.string());
        }

        std::string hex((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

        auto trim = [](std::string& s) {
            while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) {
                s.pop_back();
            }

            size_t start = 0;
            while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) {
                ++start;
            }

            if (start > 0) {
                s.erase(0, start);
            }
        };

        trim(hex);

        if (hex.empty()) {
            throw std::runtime_error(description + " file is empty: " + canon.string());
        }

        std::vector<uint8_t> bytes = hexStringToBytes(hex);
        if (bytes.size() != expectedBytes) {
            throw std::runtime_error(description + " file must contain exactly " + std::to_string(expectedBytes * 2) + " hex characters (" + std::to_string(expectedBytes) + " bytes), got " + std::to_string(bytes.size()) + " bytes");
        }

        return bytes;
    }
}