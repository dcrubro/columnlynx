// libsodium_wrapper.cpp - Libsodium Wrapper for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the GPLv3 license. See LICENSE for details.

#include <columnlynx/common/libsodium_wrapper.hpp>

namespace ColumnLynx::Utils {

    LibSodiumWrapper::LibSodiumWrapper() {
        if (sodium_init() < 0) {
            throw std::runtime_error("Failed to initialize libsodium");
        }

        if (crypto_kx_keypair(mPublicKey, mPrivateKey) != 0) {
            throw std::runtime_error("Failed to generate key pair");
        }

        log("Libsodium initialized and keypair generated");
    }

    uint8_t* LibSodiumWrapper::getPublicKey() {
        return mPublicKey;
    }

    uint8_t* LibSodiumWrapper::getPrivateKey() {
        return mPrivateKey;
    }

    uint8_t LibSodiumWrapper::generateRandomAESKey() {
        uint8_t aesKey[32]; // 256-bit key
        randombytes_buf(aesKey, sizeof(aesKey));
        return *aesKey;
    }
}