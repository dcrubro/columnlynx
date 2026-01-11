// libsodium_wrapper.hpp - Libsodium Wrapper for ColumnLynx
// Copyright (C) 2026 DcruBro
// Distributed under the terms of the GNU General Public License, either version 2 only or version 3. See LICENSES/ for details.

#pragma once

#include <sodium.h>
#include <stdexcept>
#include <string>
#include <cstdint>
#include <columnlynx/common/utils.hpp>
#include <array>
#include <vector>
#include <memory>
#include <cstring>

namespace ColumnLynx {
    using PublicKey = std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>;   // Ed25519
    using PrivateKey = std::array<uint8_t, crypto_sign_SECRETKEYBYTES>;   // Ed25519
    using PrivateSeed = std::array<uint8_t, crypto_sign_SEEDBYTES>;       // 32 bytes
    using Signature = std::array<uint8_t, crypto_sign_BYTES>;            // 64 bytes
    using SymmetricKey = std::array<uint8_t, crypto_aead_chacha20poly1305_ietf_KEYBYTES>; // 32 bytes
    using Nonce = std::array<uint8_t, crypto_aead_chacha20poly1305_ietf_NPUBBYTES>;       // 12 bytes

    using AsymPublicKey = std::array<uint8_t, crypto_box_PUBLICKEYBYTES>; // 32 bytes
    using AsymSecretKey = std::array<uint8_t, crypto_box_SECRETKEYBYTES>; // 32 bytes
    using AsymNonce = std::array<uint8_t, crypto_box_NONCEBYTES>;         // 24 bytes
}

namespace ColumnLynx::Utils {
    class LibSodiumWrapper {
        public:
            LibSodiumWrapper();

            // These are pretty self-explanatory

            uint8_t* getPublicKey();
            uint8_t* getPrivateKey();
            uint8_t* getXPublicKey() { return mXPublicKey.data(); }
            uint8_t* getXPrivateKey() { return mXPrivateKey.data(); }

            // Set the Asymmetric signing keypair. This also regenerates the corresponding encryption keypair; Dangerous!
            void setKeys(PublicKey pk, PrivateKey sk) {
                mPublicKey = pk;
                mPrivateKey = sk;

                int r;
                // Convert to Curve25519 keys for encryption
                r = crypto_sign_ed25519_pk_to_curve25519(mXPublicKey.data(), mPublicKey.data());
                r =  crypto_sign_ed25519_sk_to_curve25519(mXPrivateKey.data(), mPrivateKey.data());

                if (r != 0) {
                    throw std::runtime_error("Conversion of signing keys to encryption keys failed!");
                }
            }

            // Recompute the keypair from a given private seed; Will return false on failure
            bool recomputeKeys(PrivateSeed privateSeed, PublicKey storedPubKey);

            // Helper section

            // Generates a random 256-bit (32-byte) array
            static std::array<uint8_t, 32> generateRandom256Bit();

            // Sign a message with the stored private key
            static inline Signature signMessage(const uint8_t* msg, size_t len, const PrivateKey& sk) {
                Signature sig{};
                crypto_sign_detached(sig.data(), nullptr, msg, len, sk.data());
                return sig;
            }

            // Overloads for std::string / std::array
            static inline Signature signMessage(const std::string& msg, const PrivateKey& sk) {
                return signMessage(reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), sk);
            }

            template <size_t N>
            static inline Signature signMessage(const std::array<uint8_t, N>& msg, const PrivateKey& sk) {
                return signMessage(msg.data(), msg.size(), sk);
            }

            static inline Signature signMessage(const uint8_t* msg, size_t len, const uint8_t* sk_raw) {
                Signature sig{};
                crypto_sign_detached(sig.data(), nullptr, msg, len, sk_raw);
                return sig;
            }

            // Verify a message with a given public key
            static inline bool verifyMessage(const uint8_t* msg, size_t len, const Signature& sig, const PublicKey& pk) {
                    return crypto_sign_verify_detached(sig.data(), msg, len, pk.data()) == 0;
            }

            static inline bool verifyMessage(const std::string& msg, const Signature& sig, const PublicKey& pk) {
                return verifyMessage(reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), sig, pk);
            }

            template <size_t N>
            static inline bool verifyMessage(const std::array<uint8_t, N>& msg, const Signature& sig, const PublicKey& pk) {
                return verifyMessage(msg.data(), msg.size(), sig, pk);
            }

            static inline bool verifyMessage(const uint8_t* msg, size_t len,
                                      const Signature& sig, const uint8_t* pk_raw) {
                return crypto_sign_verify_detached(sig.data(), msg, len, pk_raw) == 0;
            }

            // Encrypt symmetrically with ChaCha20-Poly1305; returns ciphertext as bytes
            static inline std::vector<uint8_t> encryptMessage(
                const uint8_t* plaintext, size_t len,
                const SymmetricKey& key, const Nonce& nonce,
                const std::string& aad = "")
            {
                std::vector<uint8_t> ciphertext(len + crypto_aead_chacha20poly1305_ietf_ABYTES);
                unsigned long long clen = 0;
            
                if (crypto_aead_chacha20poly1305_ietf_encrypt(
                        ciphertext.data(), &clen,
                        plaintext, len,
                        reinterpret_cast<const unsigned char*>(aad.data()), aad.size(),
                        nullptr,  // no additional secret data
                        nonce.data(), key.data()) != 0)
                {
                    throw std::runtime_error("Encryption failed");
                }
            
                ciphertext.resize(static_cast<size_t>(clen));
                return ciphertext;
            }

            // Decrypt symmetrically with ChaCha20-Poly1305; Returns plaintext as bytes
            static inline std::vector<uint8_t> decryptMessage(
                const uint8_t* ciphertext, size_t len,
                const SymmetricKey& key, const Nonce& nonce,
                const std::string& aad = "")
            {
                if (len < crypto_aead_chacha20poly1305_ietf_ABYTES)
                    throw std::runtime_error("Ciphertext too short");
            
                std::vector<uint8_t> plaintext(len - crypto_aead_chacha20poly1305_ietf_ABYTES);
                unsigned long long plen = 0;

                if (crypto_aead_chacha20poly1305_ietf_decrypt(
                        plaintext.data(), &plen,
                        nullptr,
                        ciphertext, len,
                        reinterpret_cast<const unsigned char*>(aad.data()), aad.size(),
                        nonce.data(), key.data()) != 0)
                {
                    throw std::runtime_error("Decryption failed or authentication tag invalid");
                }
            
                plaintext.resize(static_cast<size_t>(plen));
                return plaintext;
            }

            // Returns a random nonce
            static inline Nonce generateNonce() {
                Nonce n{};
                randombytes_buf(n.data(), n.size());
                return n;
            }

            // Encrypt message asymmetrically; Returns ciphertext as bytes
            static inline std::vector<uint8_t> encryptAsymmetric(
                const uint8_t* plaintext, size_t len,
                const AsymNonce& nonce,
                const AsymPublicKey& recipient_pk,
                const AsymSecretKey& sender_sk)
            {
                std::vector<uint8_t> ciphertext(len + crypto_box_MACBYTES);

                if (crypto_box_easy(
                        ciphertext.data(),
                        plaintext, len,
                        nonce.data(),
                        recipient_pk.data(), sender_sk.data()) != 0)
                {
                    throw std::runtime_error("Asymmetric encryption failed");
                }
            
                return ciphertext;
            }

            // Decrypt message asymmetrically; Returns plaintext as bytes
            static inline std::vector<uint8_t> decryptAsymmetric(
                const uint8_t* ciphertext, size_t len,
                const AsymNonce& nonce,
                const AsymPublicKey& sender_pk,
                const AsymSecretKey& recipient_sk)
            {
                if (len < crypto_box_MACBYTES)
                    throw std::runtime_error("Ciphertext too short");
            
                std::vector<uint8_t> plaintext(len - crypto_box_MACBYTES);
            
                if (crypto_box_open_easy(
                        plaintext.data(),
                        ciphertext, len,
                        nonce.data(),
                        sender_pk.data(), recipient_sk.data()) != 0)
                {
                    throw std::runtime_error("Asymmetric decryption failed");
                }
            
                return plaintext;
            }

        private:
            std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> mPublicKey;
            std::array<uint8_t, crypto_sign_SECRETKEYBYTES> mPrivateKey;
            std::array<uint8_t, crypto_scalarmult_curve25519_BYTES> mXPublicKey;
            std::array<uint8_t, crypto_scalarmult_curve25519_BYTES> mXPrivateKey;
    };
}
