// net_helper.hpp - Network Helper Functions for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#pragma once
#include <asio/asio.hpp>

namespace ColumnLynx::Net::TCP {
    class NetHelper {
        public:
            inline static bool isExpectedDisconnect(const asio::error_code& ec) {
                using asio::error::operation_aborted;
                using asio::error::bad_descriptor;
                using asio::error::eof;

                return ec == operation_aborted || ec == bad_descriptor || ec == eof;
            }
    };
}