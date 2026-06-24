// crypto.cpp

#include "crypto.h"
#include <stdexcept>
#include <algorithm> 
#include <vector>

// OpenSSL headers
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

// secp256k1 for EC math
#include <secp256k1.h>

// REMOVED: generate_private_key is now handled by RNG_Buffer.

// --- Elliptic Curve Cryptography ---
bool create_public_keys(secp256k1_context* ctx,
    const PrivateKeyBytes& private_key,
    PublicKeyBytes& compressed_pubkey,
    PublicKeyBytes& uncompressed_pubkey) {
    if (!ctx) return false;

    secp256k1_pubkey pubkey_struct;
    // We still need to verify the key is valid before using it.
    if (!secp256k1_ec_seckey_verify(ctx, private_key.data())) {
        return false;
    }
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey_struct, private_key.data())) {
        return false;
    }

    compressed_pubkey.resize(33);
    size_t compressed_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, compressed_pubkey.data(), &compressed_len, &pubkey_struct, SECP256K1_EC_COMPRESSED);

    uncompressed_pubkey.resize(65);
    size_t uncompressed_len = 65;
    secp256k1_ec_pubkey_serialize(ctx, uncompressed_pubkey.data(), &uncompressed_len, &pubkey_struct, SECP256K1_EC_UNCOMPRESSED);

    return true;
}

// --- Hashing (Unchanged) ---
// ... (The sha256, ripemd160, and hash160 functions are exactly the same as before) ...
std::vector<unsigned char> sha256(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) throw std::runtime_error("EVP_MD_CTX_new failed");
    const EVP_MD* md = EVP_sha256();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, data.data(), data.size());
    unsigned int hash_len = 0;
    EVP_DigestFinal_ex(mdctx, hash.data(), &hash_len);
    EVP_MD_CTX_free(mdctx);
    hash.resize(hash_len);
    return hash;
}
std::vector<unsigned char> ripemd160(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> hash(RIPEMD160_DIGEST_LENGTH);
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) throw std::runtime_error("EVP_MD_CTX_new failed");
    const EVP_MD* md = EVP_ripemd160();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, data.data(), data.size());
    unsigned int hash_len = 0;
    EVP_DigestFinal_ex(mdctx, hash.data(), &hash_len);
    EVP_MD_CTX_free(mdctx);
    hash.resize(hash_len);
    return hash;
}
std::vector<unsigned char> hash160(const std::vector<unsigned char>& data) {
    return ripemd160(sha256(data));
}


// --- Encoding & Address Creation (Unchanged) ---
// ... (The base58_check_encode and all address/WIF functions are exactly the same as before) ...
std::string base58_check_encode(const unsigned char version_byte, const std::vector<unsigned char>& payload) {
    const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    std::vector<unsigned char> data_to_encode;
    data_to_encode.push_back(version_byte);
    data_to_encode.insert(data_to_encode.end(), payload.begin(), payload.end());
    auto checksum = sha256(sha256(data_to_encode));
    data_to_encode.insert(data_to_encode.end(), checksum.begin(), checksum.begin() + 4);
    std::string result = "";
    std::vector<unsigned char> bignum = data_to_encode;
    while (!bignum.empty()) {
        int remainder = 0;
        std::vector<unsigned char> quotient;
        bool leading = true;
        for (unsigned char byte : bignum) {
            int accumulator = remainder * 256 + byte;
            unsigned char digit = static_cast<unsigned char>(accumulator / 58);
            remainder = accumulator % 58;
            if (leading && digit == 0) {}
            else { leading = false; quotient.push_back(digit); }
        }
        result.push_back(pszBase58[remainder]);
        bignum.swap(quotient);
    }
    for (unsigned char byte : data_to_encode) { if (byte == 0) result.push_back('1'); else break; }
    std::reverse(result.begin(), result.end());
    return result;
}
std::string create_p2pkh_address(const PublicKeyBytes& public_key) {
    auto payload = hash160(public_key);
    return base58_check_encode(0x00, payload);
}
std::string create_p2sh_address(const PublicKeyBytes& public_key) {
    auto pubkey_hash = hash160(public_key);
    std::vector<unsigned char> redeem_script;
    redeem_script.push_back(0x00);
    redeem_script.push_back(0x14);
    redeem_script.insert(redeem_script.end(), pubkey_hash.begin(), pubkey_hash.end());
    auto script_hash = hash160(redeem_script);
    return base58_check_encode(0x05, script_hash);
}
std::string private_key_to_wif_compressed(const PrivateKeyBytes& private_key) {
    std::vector<unsigned char> payload = private_key;
    payload.push_back(0x01);
    return base58_check_encode(0x80, payload);
}
std::string private_key_to_wif_uncompressed(const PrivateKeyBytes& private_key) {
    return base58_check_encode(0x80, private_key);
}