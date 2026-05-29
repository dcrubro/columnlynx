// Tests for hex key file loading helpers
#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>

#include <columnlynx/common/utils.hpp>
#include <sodium.h>

int main() {
    namespace fs = std::filesystem;
    using namespace ColumnLynx::Utils;

    fs::path tempDir = fs::temp_directory_path() / "columnlynx_key_loader_test";
    fs::remove_all(tempDir);
    fs::create_directories(tempDir);

    auto publicKeyPath = tempDir / "public.key";
    auto privateKeyPath = tempDir / "private.key";

    {
        std::ofstream pub(publicKeyPath);
        pub << "00112233445566778899aabbccddeeff00112233445566778899AABBCCDDEEFF";
    }

    {
        std::ofstream priv(privateKeyPath);
        priv << "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100\n";
    }

    auto pk = loadHexArrayFromFile<crypto_sign_PUBLICKEYBYTES>(publicKeyPath.string(), "public key");
    auto sk = loadHexArrayFromFile<crypto_sign_SEEDBYTES>(privateKeyPath.string(), "private key", true);

    assert(pk[0] == 0x00 && pk[1] == 0x11 && pk.back() == 0xFF);
    assert(sk[0] == 0xFF && sk[1] == 0xEE && sk.back() == 0x00);

    bool threwMissing = false;
    try {
        (void)loadHexArrayFromFile<crypto_sign_PUBLICKEYBYTES>((tempDir / "missing.key").string(), "missing key");
    } catch (const std::exception&) {
        threwMissing = true;
    }
    assert(threwMissing && "Missing key file should throw");

    auto badLengthPath = tempDir / "bad-length.key";
    {
        std::ofstream bad(badLengthPath);
        bad << "abcd";
    }

    bool threwBadLength = false;
    try {
        (void)loadHexArrayFromFile<crypto_sign_PUBLICKEYBYTES>(badLengthPath.string(), "bad length key");
    } catch (const std::exception&) {
        threwBadLength = true;
    }
    assert(threwBadLength && "Wrong-length key file should throw");

    std::cout << "Key file loader tests passed\n";
    fs::remove_all(tempDir);
    return 0;
}