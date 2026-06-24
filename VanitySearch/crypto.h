// crypto.h

#pragma once

#include <vector>
#include <string>
#include <cstdint>

struct secp256k1_context_struct;
typedef struct secp256k1_context_struct secp256k1_context;

using PrivateKeyBytes = std::vector<unsigned char>;
using PublicKeyBytes = std::vector<unsigned char>;

// --- Core Crypto Functions ---
// REMOVED: generate_private_key is no longer needed here.

bool create_public_keys(secp256k1_context* ctx,
    const PrivateKeyBytes& private_key,
    PublicKeyBytes& compressed_pubkey,
    PublicKeyBytes& uncompressed_pubkey);

// --- Hashing ---
std::vector<unsigned char> sha256(const std::vector<unsigned char>& data);
std::vector<unsigned char> ripemd160(const std::vector<unsigned char>& data);
std::vector<unsigned char> hash160(const std::vector<unsigned char>& data);

// --- Encoding & Address Generation ---
std::string base58_check_encode(unsigned char version_byte, const std::vector<unsigned char>& payload);
std::string create_p2pkh_address(const PublicKeyBytes& public_key);
std::string create_p2sh_address(const PublicKeyBytes& public_key);
std::string private_key_to_wif_compressed(const PrivateKeyBytes& private_key);
std::string private_key_to_wif_uncompressed(const PrivateKeyBytes& private_key);