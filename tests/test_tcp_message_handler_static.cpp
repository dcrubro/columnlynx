// Tests for TCP MessageHandler static helpers
#include <cassert>
#include <iostream>

#include <columnlynx/common/net/tcp/tcp_message_handler.hpp>
#include <columnlynx/common/net/tcp/tcp_message_type.hpp>

int main() {
    using namespace ColumnLynx::Net::TCP;

    // server message special codes
    auto t1 = MessageHandler::decodeMessageType(0xFE);
    // Expect GRACEFUL_DISCONNECT mapped
    // Compare by converting back to uint8
    assert(MessageHandler::toUint8(t1) == 0xFE);

    auto t2 = MessageHandler::decodeMessageType(0xFF);
    assert(MessageHandler::toUint8(t2) == 0xFF);

    // Client message range (>= 0xA0)
    auto t3 = MessageHandler::decodeMessageType(0xA5);
    assert(MessageHandler::toUint8(t3) == 0xA5);

    // Server message range (< 0xA0) and not special
    auto t4 = MessageHandler::decodeMessageType(0x10);
    assert(MessageHandler::toUint8(t4) == 0x10);

    std::cout << "TCP MessageHandler static helpers tests passed\n";
    return 0;
}
