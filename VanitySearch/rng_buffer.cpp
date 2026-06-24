// rng_buffer.cpp

#include "rng_buffer.h"
#include <stdexcept>

#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

Seeded_RNG::Seeded_RNG() : lib_ctx(nullptr), prov(nullptr) {
    lib_ctx = OSSL_LIB_CTX_new();
    if (!lib_ctx) {
        throw std::runtime_error("Failed to create OSSL_LIB_CTX.");
    }

    // FIX: Load the provider and STORE the handle.
    prov = OSSL_PROVIDER_load(lib_ctx, "default");
    if (!prov) {
        OSSL_LIB_CTX_free(lib_ctx);
        throw std::runtime_error("Failed to load default provider into OSSL_LIB_CTX.");
    }

    // FIX: DO NOT unload the provider here.
}

Seeded_RNG::~Seeded_RNG() {
    // FIX: Clean up in the correct order. Unload the provider first, then free the context.
    if (prov) {
        OSSL_PROVIDER_unload(prov);
    }
    if (lib_ctx) {
        OSSL_LIB_CTX_free(lib_ctx);
    }
}

bool Seeded_RNG::get_private_key(PrivateKeyBytes& key) {
    key.resize(32);
    if (RAND_bytes_ex(lib_ctx, key.data(), key.size(), 0) != 1) {
        return false;
    }
    return true;
}