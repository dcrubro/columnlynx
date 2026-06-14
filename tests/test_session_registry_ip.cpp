// Tests for SessionRegistry IP allocation and lock/dealloc
#include <iostream>
#include <cassert>

#include <columnlynx/common/net/session_registry.hpp>
#include <columnlynx/common/libsodium_wrapper.hpp>

int main() {
    using namespace ColumnLynx::Net;
    using namespace ColumnLynx::Utils;

    auto &reg = SessionRegistry::getInstance();

    const uint32_t sid = 0xABCDEF01;
    reg.erase(sid);

    auto key = LibSodiumWrapper::generateRandom256Bit();
    auto state = std::make_shared<SessionState>(key, std::chrono::hours(24), 0, 0, sid);
    reg.put(sid, state);

    // Lock IP
    uint32_t ip = 0xC0A80201; // 192.168.2.1
    reg.lockIP(sid, ip);

    auto byip = reg.getByIP(ip);
    assert(byip && byip->sessionID == sid && "lockIP should populate mIPSessions");

    // deallocIP
    reg.deallocIP(sid);
    assert(reg.getByIP(ip) == nullptr && "deallocIP should remove mapping");

    // getFirstAvailableIP: choose a small /30 range to limit hosts
    uint32_t base = 0x0A000000; // 10.0.0.0
    uint8_t mask = 30; // 2 usable hosts
    uint32_t first = reg.getFirstAvailableIP(base, mask);
    assert(first != 0 && "Should find available IP in empty registry");

    // cleanup
    reg.erase(sid);

    std::cout << "SessionRegistry IP tests passed\n";
    return 0;
}
