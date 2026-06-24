// rng_buffer.h

#pragma once

#include "crypto.h"

// Forward-declare the OpenSSL structs
struct ossl_lib_ctx_st;
typedef struct ossl_lib_ctx_st OSSL_LIB_CTX;
struct ossl_provider_st;
typedef struct ossl_provider_st OSSL_PROVIDER;

// This class is NOT thread-safe. Each thread must have its own instance.
class Seeded_RNG {
public:
    Seeded_RNG();
    ~Seeded_RNG();
    bool get_private_key(PrivateKeyBytes& key);

private:
    OSSL_LIB_CTX* lib_ctx;
    // FIX: We need to store a handle to the provider to unload it later.
    OSSL_PROVIDER* prov;
};