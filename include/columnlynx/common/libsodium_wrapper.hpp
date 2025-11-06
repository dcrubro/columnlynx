// libsodium_wrapper.hpp - Libsodium Wrapper for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the GPLv3 license. See LICENSE for details.

#pragma once

#include <sodium.h>
#include <stdexcept>
#include <string>
#include <cstdint>
#include <columnlynx/common/utils.hpp>

namespace ColumnLynx::Utils {

    class LibSodiumWrapper {
        public:
            LibSodiumWrapper();

            uint8_t* getPublicKey();
            uint8_t* getPrivateKey();
            uint8_t generateRandomAESKey();

        private:
            uint8_t mPublicKey[crypto_kx_PUBLICKEYBYTES];
            uint8_t mPrivateKey[crypto_kx_SECRETKEYBYTES];
    };
}