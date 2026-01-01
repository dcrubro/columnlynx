// virtual_interface.hpp - Virtual Interface for Network Communication
// Copyright (C) 2025 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#pragma once

#include <stdexcept>
#include <cstring>
#include <cerrno>
#include <vector>
#include <iostream>
#include <columnlynx/common/utils.hpp>

#if defined(__linux__)
    #include <fcntl.h>
    #include <unistd.h>
    #include <sys/ioctl.h>
    #include <linux/if.h>
    #include <linux/if_tun.h>
    #include <arpa/inet.h>
#elif defined(__APPLE__)
    #include <sys/socket.h>
    #include <sys/kern_control.h>
    #include <sys/sys_domain.h>
    #include <net/if_utun.h>
    #include <sys/ioctl.h>
    #include <unistd.h>
    #include <arpa/inet.h>
    #include <sys/poll.h>
#elif defined(_WIN32)
    #define WIN32_LEAN_AND_MEAN
    #define WINTUN_STATIC
    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <locale>
    #include <codecvt>
    #include <wintun/wintun.h>
#endif

namespace ColumnLynx::Net {
    class VirtualInterface {
        public:
            explicit VirtualInterface(const std::string& ifName);
            ~VirtualInterface();

            bool configureIP(uint32_t clientIP, uint32_t serverIP,
                             uint8_t prefixLen, uint16_t mtu);
                             
            void resetIP();

            std::vector<uint8_t> readPacket();
            void writePacket(const std::vector<uint8_t>& packet);

            const std::string& getName() const;
            int getFd() const; // For ASIO integration (on POSIX)

            static inline std::string ipv4ToString(uint32_t ip, bool flip = true) {
                struct in_addr addr;

                if (flip)
                    addr.s_addr = htonl(ip);
                else
                    addr.s_addr = ip;
            
                char buf[INET_ADDRSTRLEN];
                if (!inet_ntop(AF_INET, &addr, buf, sizeof(buf)))
                    return "0.0.0.0";
            
                return std::string(buf);
            }

            static inline uint32_t stringToIpv4(const std::string &ipStr) {
                struct in_addr addr;
                
                if (inet_pton(AF_INET, ipStr.c_str(), &addr) != 1) {
                    return 0; // "0.0.0.0"
                }
            
                return ntohl(addr.s_addr);
            }

            static inline std::string ipv6ToString(IPv6Addr &ip,
                                       bool flip = false)
            {
                struct in6_addr addr;
            
                if (flip) {
                    IPv6Addr flipped;
                    for (size_t i = 0; i < 16; ++i)
                        flipped[i] = ip[15 - i];
                    memcpy(addr.s6_addr, flipped.data(), 16);
                } else {
                    memcpy(addr.s6_addr, ip.data(), 16);
                }
            
                char buf[INET6_ADDRSTRLEN];
                if (!inet_ntop(AF_INET6, &addr, buf, sizeof(buf)))
                    return "::";  // Fallback
            
                return std::string(buf);
            }

            static inline IPv6Addr stringToIpv6(const std::string &ipStr)
            {
                IPv6Addr result{};
                struct in6_addr addr;
            
                if (inet_pton(AF_INET6, ipStr.c_str(), &addr) != 1) {
                    // "::"
                    result.fill(0);
                    return result;
                }
            
                memcpy(result.data(), addr.s6_addr, 16);
                return result;
            }

            static inline uint32_t prefixLengthToNetmask(uint8_t prefixLen) {
                if (prefixLen == 0) return 0;
                uint32_t mask = (0xFFFFFFFF << (32 - prefixLen)) & 0xFFFFFFFF;
                return htonl(mask);    // convert to network byte order
            }

        private:
            bool mApplyLinuxIP(uint32_t clientIP, uint32_t serverIP, uint8_t prefixLen, uint16_t mtu);
            bool mApplyMacOSIP(uint32_t clientIP, uint32_t serverIP, uint8_t prefixLen, uint16_t mtu);
            bool mApplyWindowsIP(uint32_t clientIP, uint32_t serverIP, uint8_t prefixLen, uint16_t mtu);

            std::string mIfName;
            int mFd;           // POSIX
        #if defined(_WIN32)
            WINTUN_ADAPTER_HANDLE mAdapter = nullptr;
            WINTUN_SESSION_HANDLE mSession = nullptr;
            HANDLE mHandle = nullptr;
        #endif
    };
}