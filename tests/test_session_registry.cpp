// Simple unit tests for SessionRegistry
#include <cassert>
#include <iostream>
#include <chrono>

#include <columnlynx/common/net/session_registry.hpp>
#include <columnlynx/common/libsodium_wrapper.hpp>

int main() {
    using namespace ColumnLynx::Net;
    using namespace ColumnLynx::Utils;

    auto &reg = SessionRegistry::getInstance();

    // Use a unique session id to avoid colliding with any running instance
    const uint32_t sid = 0xDEADBEEF;
    // ensure clean state
    reg.erase(sid);

    auto key = LibSodiumWrapper::generateRandom256Bit();
    auto state = std::make_shared<SessionState>(key, std::chrono::hours(24), 0xC0A80101 /*192.168.1.1*/, 0, sid);

    reg.put(sid, state);

    assert(reg.exists(sid) && "Session should exist after put()");

    auto got = reg.get(sid);
    assert(got && got->sessionID == sid && "get() should return stored session");

    auto byip = reg.getByIP(0xC0A80101);
    assert(byip && byip->sessionID == sid && "getByIP() should find session by client IP");

    // Erase and verify removed
    reg.erase(sid);
    assert(!reg.exists(sid) && "Session should not exist after erase()");
    assert(reg.getByIP(0xC0A80101) == nullptr && "getByIP() should return nullptr after erase");

    // Test cleanupExpired: insert an already-expired session
    const uint32_t sid2 = 0xFEEDBEEF;
    reg.erase(sid2);
    auto expiredState = std::make_shared<SessionState>(key, std::chrono::seconds(0), 0xC0A80102, 0, sid2);
    reg.put(sid2, expiredState);
    // Force cleanup
    reg.cleanupExpired();
    assert(!reg.exists(sid2) && "Expired session should be removed by cleanupExpired()");

    std::cout << "SessionRegistry tests passed\n";
    return 0;
}
