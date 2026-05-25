// Tests for LibSodiumWrapper: random, symmetric encrypt/decrypt, sign/verify
#include <iostream>
#include <cassert>

#include <columnlynx/common/libsodium_wrapper.hpp>

int main() {
    using namespace ColumnLynx::Utils;

    // Random bytes uniqueness
    auto a = LibSodiumWrapper::generateRandom256Bit();
    auto b = LibSodiumWrapper::generateRandom256Bit();
    assert(a != b && "generateRandom256Bit() should produce different outputs (very likely)");

    // Symmetric encrypt/decrypt roundtrip
    ColumnLynx::SymmetricKey key = {};
    for (size_t i = 0; i < key.size(); ++i) key[i] = static_cast<uint8_t>(i);
    auto nonce = LibSodiumWrapper::generateNonce();

    std::string plaintext = "The quick brown fox jumps over the lazy dog";
    auto ct = LibSodiumWrapper::encryptMessage(reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size(), key, nonce, "aad");
    auto pt = LibSodiumWrapper::decryptMessage(ct.data(), ct.size(), key, nonce, "aad");
    std::string recovered(pt.begin(), pt.end());
    assert(recovered == plaintext && "decrypt should recover original plaintext");

    // Sign and verify
    ColumnLynx::PrivateKey sk{}; ColumnLynx::PublicKey pk{};
    randombytes_buf(sk.data(), sk.size());
    // naive keypair generation for test purposes: use libsodium functions via wrapper
    // generate a real keypair using crypto_sign
    if (crypto_sign_keypair(pk.data(), sk.data()) != 0) {
        std::cerr << "Failed to generate keypair\n";
        return 2;
    }

    auto sig = LibSodiumWrapper::signMessage(plaintext, sk);
    bool ok = LibSodiumWrapper::verifyMessage(plaintext, sig, pk);
    assert(ok && "Signature should verify");

    std::cout << "LibSodiumWrapper tests passed\n";
    return 0;
}
