// virtual_interface.cpp - Virtual Interface for Network Communication
// Copyright (C) 2025 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#include <columnlynx/common/net/virtual_interface.hpp>

// This is all fucking voodoo dark magic.

#if defined(_WIN32)

static HMODULE gWintun = nullptr;

static WINTUN_OPEN_ADAPTER_FUNC*           pWintunOpenAdapter;
static WINTUN_START_SESSION_FUNC*          pWintunStartSession;
static WINTUN_END_SESSION_FUNC*            pWintunEndSession;
static WINTUN_GET_READ_WAIT_EVENT_FUNC*    pWintunGetReadWaitEvent;
static WINTUN_RECEIVE_PACKET_FUNC*         pWintunReceivePacket;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC* pWintunReleaseReceivePacket;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC*   pWintunAllocateSendPacket;
static WINTUN_SEND_PACKET_FUNC*            pWintunSendPacket;
static WINTUN_CREATE_ADAPTER_FUNC*         pWintunCreateAdapter;

static void InitializeWintun()
{
    if (gWintun)
        return;

    gWintun = LoadLibraryExW(
        L"wintun.dll",
        nullptr,
        LOAD_LIBRARY_SEARCH_APPLICATION_DIR
    );

    if (!gWintun)
        throw std::runtime_error("Failed to load wintun.dll");

#define RESOLVE(name, type)                                      \
    p##name = reinterpret_cast<type*>(                           \
        GetProcAddress(gWintun, #name));                          \
    if (!p##name)                                                 \
        throw std::runtime_error("Missing Wintun symbol: " #name);

    RESOLVE(WintunOpenAdapter,           WINTUN_OPEN_ADAPTER_FUNC)
    RESOLVE(WintunStartSession,          WINTUN_START_SESSION_FUNC)
    RESOLVE(WintunEndSession,            WINTUN_END_SESSION_FUNC)
    RESOLVE(WintunGetReadWaitEvent,      WINTUN_GET_READ_WAIT_EVENT_FUNC)
    RESOLVE(WintunReceivePacket,         WINTUN_RECEIVE_PACKET_FUNC)
    RESOLVE(WintunReleaseReceivePacket,  WINTUN_RELEASE_RECEIVE_PACKET_FUNC)
    RESOLVE(WintunAllocateSendPacket,    WINTUN_ALLOCATE_SEND_PACKET_FUNC)
    RESOLVE(WintunSendPacket,            WINTUN_SEND_PACKET_FUNC)
    RESOLVE(WintunCreateAdapter,         WINTUN_CREATE_ADAPTER_FUNC)

#undef RESOLVE
}

#endif // _WIN32

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
        // TL;DR: macOS doesn't really have a "device file" for TUN/TAP like Linux. Instead we have to request a "system control socket" from the kernel.
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
        sc.sc_unit = 0; // 0 = auto-assign next utunX

        if (connect(mFd, (struct sockaddr*)&sc, sizeof(sc)) < 0) {
            if (errno == EPERM)
                throw std::runtime_error("connect(AF_SYS_CONTROL) failed: Insufficient permissions (try running as root)");
            throw std::runtime_error("connect(AF_SYS_CONTROL) failed: " + std::string(strerror(errno)));
        }

        // Retrieve actual utun device name via UTUN_OPT_IFNAME
        char ifname[IFNAMSIZ];
        socklen_t ifname_len = sizeof(ifname);
        if (getsockopt(mFd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &ifname_len) == 0) {
            mIfName = ifname; // Update to actual assigned name
        } else {
            mIfName = "utun0"; // Fallback (should not happen)
        }

        Utils::log("VirtualInterface: opened macOS UTUN: " + mIfName);

    #elif defined(_WIN32)

        InitializeWintun();

        mAdapter = pWintunOpenAdapter(ifaceName);

        if (!mAdapter) {
            mAdapter = pWintunCreateAdapter(
                ifaceName,
                L"ColumnLynx",
                nullptr
            );
        }

        if (!mAdapter)
            throw std::runtime_error("Failed to open or create Wintun adapter");

        mSession = pWintunStartSession(mAdapter, 0x200000);
        if (!mSession)
            throw std::runtime_error("Failed to start Wintun session");

        mHandle = pWintunGetReadWaitEvent(mSession);
        mFd = -1;

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
        if (mSession)
            pWintunEndSession(mSession);
    #endif
    }

    // ------------------------------ Read ------------------------------
    std::vector<uint8_t> VirtualInterface::readPacket() {
    #if defined(__linux__)

        // Linux TUN: blocking read is fine, unblocks on fd close / EINTR
        std::vector<uint8_t> buf(4096);
        ssize_t n = read(mFd, buf.data(), buf.size());
        if (n < 0) {
            if (errno == EINTR) {
                return {}; // Interrupted, just return empty
            }
            throw std::runtime_error("read() failed: " + std::string(strerror(errno)));
        }
        buf.resize(n);
        return buf;

    #elif defined(__APPLE__)

        // macOS utun: must poll, or read() can block forever
        std::vector<uint8_t> buf(4096);

        struct pollfd pfd;
        pfd.fd = mFd;
        pfd.events = POLLIN;

        // timeout in ms; keep it small so shutdown is responsive
        int ret = poll(&pfd, 1, 200);

        if (ret == 0) {
            // No data yet
            return {};
        }

        if (ret < 0) {
            if (errno == EINTR) {
                return {}; // Interrupted by signal
            }
            throw std::runtime_error("poll() failed: " + std::string(strerror(errno)));
        }

        if (!(pfd.revents & POLLIN)) {
            return {};
        }

        ssize_t n = read(mFd, buf.data(), buf.size());
        if (n <= 0) {
            // 0 or -1: treat as EOF or transient; you can decide how aggressive to be
            return {};
        }

        if (n > 4) {
            // Drop macOS UTUN header (4 bytes)
            std::memmove(buf.data(), buf.data() + 4, n - 4);
            buf.resize(n - 4);
        } else {
            return {};
        }

        return buf;

    #elif defined(_WIN32)

        DWORD size = 0;
        BYTE* packet = pWintunReceivePacket(mSession, &size);
        if (!packet)
            return {};

        std::vector<uint8_t> buf(packet, packet + size);
        pWintunReleaseReceivePacket(mSession, packet);
        return buf;

    #else
        return {};
    #endif
    }

    // ------------------------------ Write ------------------------------
    void VirtualInterface::writePacket(const std::vector<uint8_t>& packet) {
    #if defined(__linux__)

        // Linux TUN expects raw IP packet
        ssize_t n = write(mFd, packet.data(), packet.size());
        if (n < 0)
            throw std::runtime_error("write() failed: " + std::string(strerror(errno)));

    #elif defined(__APPLE__)

        if (packet.empty())
            return;

        // Detect IPv4 or IPv6
        uint8_t version = packet[0] >> 4;
        uint32_t af;

        if (version == 4) {
            af = htonl(AF_INET);
        } else if (version == 6) {
            af = htonl(AF_INET6);
        } else {
            throw std::runtime_error("writePacket(): unknown IP version");
        }

        // Prepend 4-byte AF header
        std::vector<uint8_t> out(packet.size() + 4);
        memcpy(out.data(), &af, 4);
        memcpy(out.data() + 4, packet.data(), packet.size());

        ssize_t n = write(mFd, out.data(), out.size());
        if (n < 0)
            throw std::runtime_error("utun write() failed: " + std::string(strerror(errno)));

    #elif defined(_WIN32)

        BYTE* tx = pWintunAllocateSendPacket(
            mSession,
            static_cast<DWORD>(packet.size())
        );

        if (!tx)
            throw std::runtime_error("WintunAllocateSendPacket failed");

        memcpy(tx, packet.data(), packet.size());
        pWintunSendPacket(mSession, tx);

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

    void VirtualInterface::resetIP() {
    #if defined(__linux__)
        char cmd[512];
        snprintf(cmd, sizeof(cmd),
                 "ip addr flush dev %s",
                 mIfName.c_str()
        );
        system(cmd);
    #elif defined(__APPLE__)
        char cmd[512];
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
    #elif defined(_WIN32)
        char cmd[256];
        snprintf(cmd, sizeof(cmd),
            "netsh interface ip set address name=\"%s\" dhcp",
            mIfName.c_str()
        );
        system(cmd);
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
        std::string prefixStr = ipv4ToString(prefixLengthToNetmask(prefixLen), false);
        Utils::debug("Prefix string: " + prefixStr);
    
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
                "ifconfig %s inet %s %s mtu %d netmask %s up",
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