// virtual_interface.cpp - Virtual Interface for Network Communication
// Copyright (C) 2025 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#include <columnlynx/common/net/virtual_interface.hpp>

// This is all fucking voodoo dark magic.

namespace ColumnLynx::Net {
    // ------------------------------ Constructor ------------------------------
    VirtualInterface::VirtualInterface(const std::string& ifName)
        : mIfName(ifName), mFd(-1)
    {
    #if defined(__linux__)
        // ---- Linux: /dev/net/tun ----
        mFd = open("/dev/net/tun", O_RDWR);
        if (mFd < 0)
            throw std::runtime_error("Failed to open /dev/net/tun: " + std::string(strerror(errno)));

        struct ifreq ifr {};
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        std::strncpy(ifr.ifr_name, ifName.c_str(), IFNAMSIZ);

        if (ioctl(mFd, TUNSETIFF, &ifr) < 0) {
            close(mFd);
            throw std::runtime_error("TUNSETIFF failed: " + std::string(strerror(errno)));
        }

    #elif defined(__APPLE__)
        // ---- macOS: UTUN (system control socket) ----
        mFd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
        if (mFd < 0)
            throw std::runtime_error("socket(PF_SYSTEM) failed: " + std::string(strerror(errno)));

        struct ctl_info ctlInfo {};
        std::strncpy(ctlInfo.ctl_name, UTUN_CONTROL_NAME, sizeof(ctlInfo.ctl_name));
        if (ioctl(mFd, CTLIOCGINFO, &ctlInfo) == -1)
            throw std::runtime_error("ioctl(CTLIOCGINFO) failed: " + std::string(strerror(errno)));

        struct sockaddr_ctl sc {};
        sc.sc_len = sizeof(sc);
        sc.sc_family = AF_SYSTEM;
        sc.ss_sysaddr = AF_SYS_CONTROL;
        sc.sc_id = ctlInfo.ctl_id;
        sc.sc_unit = 0; // lynx0 (0 = auto-assign)

        if (connect(mFd, (struct sockaddr*)&sc, sizeof(sc)) < 0) {
            if (errno == EPERM)
                throw std::runtime_error("connect(AF_SYS_CONTROL) failed: Insufficient permissions (try running as root)");
            throw std::runtime_error("connect(AF_SYS_CONTROL) failed: " + std::string(strerror(errno)));
        }

        // Retrieve actual utun device name
        struct sockaddr_storage addr;
        socklen_t addrlen = sizeof(addr);
        if (getsockname(mFd, (struct sockaddr*)&addr, &addrlen) == 0) {
            const struct sockaddr_ctl* addr_ctl = (const struct sockaddr_ctl*)&addr;
            mIfName = "utun" + std::to_string(addr_ctl->sc_unit - 1);
        } else {
            mIfName = "utunX";
        }

    #elif defined(_WIN32)
        // ---- Windows: Wintun (WireGuard virtual adapter) ----
        WINTUN_ADAPTER_HANDLE adapter =
            WintunOpenAdapter(L"ColumnLynx", std::wstring(ifName.begin(), ifName.end()).c_str());
        if (!adapter)
            throw std::runtime_error("Wintun adapter not found or not installed");

        WINTUN_SESSION_HANDLE session =
            WintunStartSession(adapter, 0x200000); // ring buffer size
        if (!session)
            throw std::runtime_error("Failed to start Wintun session");

        mHandle = WintunGetReadWaitEvent(session);
        mFd = -1; // not used on Windows
        mIfName = ifName;

    #else
        throw std::runtime_error("Unsupported platform");
    #endif
    }

    // ------------------------------ Destructor ------------------------------
    VirtualInterface::~VirtualInterface() {
    #if defined(__linux__) || defined(__APPLE__)
        if (mFd >= 0)
            close(mFd);
    #elif defined(_WIN32)
        // Wintun sessions need explicit stop
        // (assuming you stored the session handle as member)
        // WintunEndSession(mSession);
    #endif
    }

    // ------------------------------ Read ------------------------------
    std::vector<uint8_t> VirtualInterface::readPacket() {
    #if defined(__linux__) || defined(__APPLE__)
        std::vector<uint8_t> buf(4096);
        ssize_t n = read(mFd, buf.data(), buf.size());
        if (n < 0) {
            if (errno == EINTR) {
                return {}; // Interrupted, return empty
            }
            throw std::runtime_error("read() failed: " + std::string(strerror(errno)));
        }
        buf.resize(n);
        return buf;

    #elif defined(_WIN32)
        WINTUN_PACKET* packet = WintunReceivePacket(mSession, nullptr);
        if (!packet) return {};
        std::vector<uint8_t> buf(packet->Data, packet->Data + packet->Length);
        WintunReleaseReceivePacket(mSession, packet);
        return buf;
    #else
        return {};
    #endif
    }

    // ------------------------------ Write ------------------------------
    void VirtualInterface::writePacket(const std::vector<uint8_t>& packet) {
    #if defined(__linux__) || defined(__APPLE__)
        ssize_t n = write(mFd, packet.data(), packet.size());
        if (n < 0)
            throw std::runtime_error("write() failed: " + std::string(strerror(errno)));

    #elif defined(_WIN32)
        WINTUN_PACKET* tx = WintunAllocateSendPacket(mSession, (DWORD)packet.size());
        if (!tx) throw std::runtime_error("WintunAllocateSendPacket failed");
        memcpy(tx->Data, packet.data(), packet.size());
        WintunSendPacket(mSession, tx);
    #endif
    }

    // ------------------------------ Accessors ------------------------------
    const std::string& VirtualInterface::getName() const { return mIfName; }

    int VirtualInterface::getFd() const { return mFd; }

    // ------------------------------------------------------------
    //  IP CONFIGURATION
    // ------------------------------------------------------------
    bool VirtualInterface::configureIP(uint32_t clientIP, uint32_t serverIP,
                                       uint8_t prefixLen, uint16_t mtu)
    {
    #if defined(__linux__)
        return mApplyLinuxIP(clientIP, serverIP, prefixLen, mtu);
    #elif defined(__APPLE__)
        return mApplyMacOSIP(clientIP, serverIP, prefixLen, mtu);
    #elif defined(_WIN32)
        return mApplyWindowsIP(clientIP, serverIP, prefixLen, mtu);
    #else
        return false;
    #endif
    }
    
    // ------------------------------------------------------------
    // Linux
    // ------------------------------------------------------------
    bool VirtualInterface::mApplyLinuxIP(uint32_t clientIP, uint32_t serverIP,
                                        uint8_t prefixLen, uint16_t mtu)
    {
        char cmd[512];
    
        std::string ipStr = ipv4ToString(clientIP);
        std::string peerStr = ipv4ToString(serverIP);
    
        // Wipe the current config
        snprintf(cmd, sizeof(cmd),
                 "ip addr flush dev %s",
                 mIfName.c_str()
        );
        system(cmd);

        snprintf(cmd, sizeof(cmd),
                 "ip addr add %s/%d peer %s dev %s",
                 ipStr.c_str(), prefixLen, peerStr.c_str(), mIfName.c_str());
        system(cmd);
    
        snprintf(cmd, sizeof(cmd),
                 "ip link set dev %s up mtu %d", mIfName.c_str(), mtu);
        system(cmd);
    
        return true;
    }
    
    // ------------------------------------------------------------
    // macOS (utun)
    // ------------------------------------------------------------
    bool VirtualInterface::mApplyMacOSIP(uint32_t clientIP, uint32_t serverIP,
                                        uint8_t prefixLen, uint16_t mtu)
    {
        char cmd[512];
    
        std::string ipStr = ipv4ToString(clientIP);
        std::string peerStr = ipv4ToString(serverIP);
        std::string prefixStr = ipv4ToString(prefixLen);
    
        // Reset
        snprintf(cmd, sizeof(cmd),
                 "ifconfig %s inet 0.0.0.0 delete",
                mIfName.c_str()
        );
        system(cmd);

        snprintf(cmd, sizeof(cmd),
                 "ifconfig %s inet6 :: delete",
                mIfName.c_str()
        );
        system(cmd);

        // Set
        snprintf(cmd, sizeof(cmd),
                "ifconfig %s %s %s mtu %d netmask %s up",
                 mIfName.c_str(), ipStr.c_str(), peerStr.c_str(), mtu, prefixStr.c_str());
        system(cmd);

        Utils::log("Executed command: " + std::string(cmd));
    
        return true;
    }
    
    // ------------------------------------------------------------
    // Windows (Wintun)
    // ------------------------------------------------------------
    bool VirtualInterface::mApplyWindowsIP(uint32_t clientIP,
                                       uint32_t serverIP,
                                       uint8_t prefixLen,
                                       uint16_t mtu)
    {
    #ifdef _WIN32
        std::string ip  = ipv4ToString(clientIP);
        std::string gw  = ipv4ToString(serverIP);
        std::string mask;

        // Convert prefixLen → subnet mask
        uint32_t maskInt = (prefixLen == 0) ? 0 : (0xFFFFFFFF << (32 - prefixLen));
        mask = ipv4ToString(maskInt);

        char cmd[256];

        // 1. Set the static IP + mask + gateway
        snprintf(cmd, sizeof(cmd),
            "netsh interface ip set address name=\"%s\" static %s %s %s",
            mIfName.c_str(), ip.c_str(), mask.c_str(), gw.c_str()
        );
        system(cmd);

        // 2. Set MTU (separate command)
        snprintf(cmd, sizeof(cmd),
            "netsh interface ipv4 set subinterface \"%s\" mtu=%u store=persistent",
            mIfName.c_str(), mtu
        );
        system(cmd);

        return true;
    #else
        return false;
    #endif
    }
} // namespace ColumnLynx::Net