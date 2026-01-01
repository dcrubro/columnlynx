// libsodium_wrapper.cpp - Libsodium Wrapper for ColumnLynx
// Copyright (C) 2025 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#include <columnlynx/common/libsodium_wrapper.hpp>

namespace ColumnLynx::Utils {

    LibSodiumWrapper::LibSodiumWrapper() {
        if (sodium_init() < 0) {
            throw std::runtime_error("Failed to initialize libsodium");
        }

        // Generate keypair
        if (crypto_sign_keypair(mPublicKey.data(), mPrivateKey.data()) != 0) {
            throw std::runtime_error("Failed to generate key pair");
        }

        int r;
        // Convert to Curve25519 keys for encryption
        r = crypto_sign_ed25519_pk_to_curve25519(mXPublicKey.data(), mPublicKey.data());
        r =  crypto_sign_ed25519_sk_to_curve25519(mXPrivateKey.data(), mPrivateKey.data());

        if (r != 0) {
            throw std::runtime_error("Conversion of signing keys to encryption keys failed!");
        }

        log("Libsodium initialized and keypair generated");
    }

    uint8_t* LibSodiumWrapper::getPublicKey() {
        return mPublicKey.data();
    }

    uint8_t* LibSodiumWrapper::getPrivateKey() {
        return mPrivateKey.data();
    }

    std::array<uint8_t, 32> LibSodiumWrapper::generateRandom256Bit() {
        std::array<uint8_t, 32> randbytes; // 256 bits
        randombytes_buf(randbytes.data(), randbytes.size());
        return randbytes;
    }

    bool LibSodiumWrapper::recomputeKeys(PrivateSeed privateSeed, PublicKey storedPubKey) {
        int res = crypto_sign_seed_keypair(mPublicKey.data(), mPrivateKey.data(), privateSeed.data());

        if (res != 0) {
            return false;
        }

        // Convert to Curve25519 keys for encryption
        res = crypto_sign_ed25519_pk_to_curve25519(mXPublicKey.data(), mPublicKey.data());
        res =  crypto_sign_ed25519_sk_to_curve25519(mXPrivateKey.data(), mPrivateKey.data());

        if (res != 0) {
            return false;
        }

        // Compare to stored for verification
        if (sodium_memcmp(mPublicKey.data(), storedPubKey.data(), crypto_sign_PUBLICKEYBYTES) != 0) {
            return false;
        }

        return true;
    }
}