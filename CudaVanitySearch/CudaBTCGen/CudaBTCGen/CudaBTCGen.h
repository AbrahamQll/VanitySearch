#pragma once

#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include <stdint.h>

// secp256k1 Prime P
#define P_0 0xFFFFFC2F
#define P_1 0xFFFFFFFE
#define P_2 0xFFFFFFFF
#define P_3 0xFFFFFFFF
#define P_4 0xFFFFFFFF
#define P_5 0xFFFFFFFF
#define P_6 0xFFFFFFFF
#define P_7 0xFFFFFFFF

// SHA-256 Helpers
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sigma0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define Sigma1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sigma0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define sigma1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

// RIPEMD-160 Helpers
#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define F1(x, y, z) ((x) ^ (y) ^ (z))
#define F2(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define F3(x, y, z) (((x) | ~(y)) ^ (z))
#define F4(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define F5(x, y, z) ((x) ^ ((y) | ~(z)))

// Left Lane Round Steps (with constants)
#define FF(a, b, c, d, e, x, s) { \
    a += F1(b, c, d) + x; \
    a = ROL(a, s) + e; \
    c = ROL(c, 10); \
}
#define GG(a, b, c, d, e, x, s) { \
    a += F2(b, c, d) + x + 0x5A827999; \
    a = ROL(a, s) + e; \
    c = ROL(c, 10); \
}
#define HH(a, b, c, d, e, x, s) { \
    a += F3(b, c, d) + x + 0x6ED9EBA1; \
    a = ROL(a, s) + e; \
    c = ROL(c, 10); \
}
#define II(a, b, c, d, e, x, s) { \
    a += F4(b, c, d) + x + 0x8F1BBCDC; \
    a = ROL(a, s) + e; \
    c = ROL(c, 10); \
}
#define JJ(a, b, c, d, e, x, s) { \
    a += F5(b, c, d) + x + 0xA953FD4E; \
    a = ROL(a, s) + e; \
    c = ROL(c, 10); \
}

// Right Lane Round Steps (with constants)
#define FFF(a, b, c, d, e, x, s) { \
    a += F5(b, c, d) + x + 0x50A28BE6; \
    a = ROL(a, s) + e; \
    c = ROL(c, 10); \
}
#define GGG(a, b, c, d, e, x, s) { \
    a += F4(b, c, d) + x + 0x5C4DD124; \
    a = ROL(a, s) + e; \
    c = ROL(c, 10); \
}
#define HHH(a, b, c, d, e, x, s) { \
    a += F3(b, c, d) + x + 0x6D703EF3; \
    a = ROL(a, s) + e; \
    c = ROL(c, 10); \
}
#define III(a, b, c, d, e, x, s) { \
    a += F2(b, c, d) + x + 0x7A6D76E9; \
    a = ROL(a, s) + e; \
    c = ROL(c, 10); \
}
#define JJJ(a, b, c, d, e, x, s) { \
    a += F1(b, c, d) + x; \
    a = ROL(a, s) + e; \
    c = ROL(c, 10); \
}

struct uint256 {
    uint32_t v[8];
};

struct ec_point_affine {
    uint256 x;
    uint256 y;
};

struct ec_point_jacobian {
    uint256 x;
    uint256 y;
    uint256 z;
};

struct GPUResult {
    uint8_t compressed[20];
    uint8_t uncompressed[20];
    uint8_t segwit[20];
};

// ==========================================
// DEVICE CRYPTOGRAPHIC PIPELINES
// ==========================================

__device__ __forceinline__ uint32_t swab32(uint32_t val) {
    return __byte_perm(val, 0, 0x0123);
}

__device__ __forceinline__ void add_uint256_uint64(uint256* a, uint64_t b) {
    uint64_t carry = b;
    for (int i = 0; i < 8; ++i) {
        uint64_t sum = (uint64_t)a->v[i] + carry;
        a->v[i] = (uint32_t)sum;
        carry = sum >> 32;
    }
}

__device__ __forceinline__ void mod_add(const uint256* a, const uint256* b, uint256* r) {
    uint64_t carry = 0;
    uint256 sum;
    for (int i = 0; i < 8; ++i) {
        uint64_t s = (uint64_t)a->v[i] + b->v[i] + carry;
        sum.v[i] = (uint32_t)s;
        carry = s >> 32;
    }

    uint256 sub;
    uint64_t borrow = 0;
    uint32_t p[8] = { P_0, P_1, P_2, P_3, P_4, P_5, P_6, P_7 };
    for (int i = 0; i < 8; ++i) {
        uint64_t diff = (uint64_t)sum.v[i] - p[i] - borrow;
        sub.v[i] = (uint32_t)diff;
        borrow = (diff >> 63) & 1;
    }

    if (carry || !borrow) {
        *r = sub;
    }
    else {
        *r = sum;
    }
}

__device__ __forceinline__ void mod_sub(const uint256* a, const uint256* b, uint256* r) {
    uint256 diff;
    uint64_t borrow = 0;
    for (int i = 0; i < 8; ++i) {
        uint64_t d = (uint64_t)a->v[i] - b->v[i] - borrow;
        diff.v[i] = (uint32_t)d;
        borrow = (d >> 63) & 1;
    }

    if (borrow) {
        uint32_t p[8] = { P_0, P_1, P_2, P_3, P_4, P_5, P_6, P_7 };
        uint64_t carry = 0;
        for (int i = 0; i < 8; ++i) {
            uint64_t s = (uint64_t)diff.v[i] + p[i] + carry;
            r->v[i] = (uint32_t)s;
            carry = s >> 32;
        }
    }
    else {
        *r = diff;
    }
}

__device__ __forceinline__ void multiply_256(const uint256* a, const uint256* b, uint32_t* r) {
    for (int i = 0; i < 16; ++i) r[i] = 0;

    for (int i = 0; i < 8; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < 8; ++j) {
            uint64_t prod = (uint64_t)a->v[i] * b->v[j] + r[i + j] + carry;
            r[i + j] = (uint32_t)prod;
            carry = prod >> 32;
        }
        int k = i + 8;
        while (carry > 0 && k < 16) {
            uint64_t sum = (uint64_t)r[k] + carry;
            r[k] = (uint32_t)sum;
            carry = sum >> 32;
            k++;
        }
    }
}

__device__ __forceinline__ void mod_reduce(const uint32_t* r, uint256* out) {
    uint32_t h_shift[9] = { 0 };
    for (int i = 0; i < 8; ++i) {
        h_shift[i + 1] = r[i + 8];
    }

    uint32_t h_mul[9] = { 0 };
    uint64_t carry = 0;
    for (int i = 0; i < 8; ++i) {
        uint64_t prod = (uint64_t)r[i + 8] * 977 + carry;
        h_mul[i] = (uint32_t)prod;
        carry = prod >> 32;
    }
    h_mul[8] = (uint32_t)carry;

    uint32_t x_prime[9] = { 0 };
    carry = 0;
    for (int i = 0; i < 8; ++i) {
        uint64_t sum = (uint64_t)r[i] + h_shift[i] + h_mul[i] + carry;
        x_prime[i] = (uint32_t)sum;
        carry = sum >> 32;
    }
    uint64_t sum9 = (uint64_t)h_shift[8] + h_mul[8] + carry;
    x_prime[8] = (uint32_t)sum9;
    uint32_t carry9 = sum9 >> 32;

    uint64_t h2 = x_prime[8] + ((uint64_t)carry9 << 32);
    uint32_t h2_shift[3] = { 0, (uint32_t)h2, (uint32_t)(h2 >> 32) };

    uint64_t h2_mul_val = h2 * 977;
    uint32_t h2_mul[2] = { (uint32_t)h2_mul_val, (uint32_t)(h2_mul_val >> 32) };

    uint32_t x_double_prime[8] = { 0 };
    carry = 0;
    for (int i = 0; i < 8; ++i) {
        uint32_t val_shift = (i < 3) ? h2_shift[i] : 0;
        uint32_t val_mul = (i < 2) ? h2_mul[i] : 0;
        uint64_t sum = (uint64_t)x_prime[i] + val_shift + val_mul + carry;
        x_double_prime[i] = (uint32_t)sum;
        carry = sum >> 32;
    }

    if (carry > 0) {
        uint64_t final_add = carry * 977;
        uint64_t final_shift = carry;
        uint64_t c_sum = 0;
        for (int i = 0; i < 8; ++i) {
            uint32_t term_shift = (i == 1) ? final_shift : 0;
            uint32_t term_mul = (i == 0) ? final_add : 0;
            uint64_t sum = (uint64_t)x_double_prime[i] + term_shift + term_mul + c_sum;
            x_double_prime[i] = (uint32_t)sum;
            c_sum = sum >> 32;
        }
    }

    uint32_t p[8] = { P_0, P_1, P_2, P_3, P_4, P_5, P_6, P_7 };
    for (int pass = 0; pass < 2; ++pass) {
        uint32_t sub[8];
        uint64_t borrow = 0;
        for (int i = 0; i < 8; ++i) {
            uint64_t diff = (uint64_t)x_double_prime[i] - p[i] - borrow;
            sub[i] = (uint32_t)diff;
            borrow = (diff >> 63) & 1;
        }
        if (!borrow) {
            for (int i = 0; i < 8; ++i) x_double_prime[i] = sub[i];
        }
        else {
            break;
        }
    }

    for (int i = 0; i < 8; ++i) out->v[i] = x_double_prime[i];
}

__device__ __forceinline__ void mod_mul(const uint256* a, const uint256* b, uint256* r) {
    uint32_t temp_512[16];
    multiply_256(a, b, temp_512);
    mod_reduce(temp_512, r);
}

__device__ __forceinline__ void mod_inv(const uint256* a, uint256* r) {
    uint256 exp;
    exp.v[0] = 0xFFFFFC2D;
    exp.v[1] = 0xFFFFFFFE;
    exp.v[2] = 0xFFFFFFFF;
    exp.v[3] = 0xFFFFFFFF;
    exp.v[4] = 0xFFFFFFFF;
    exp.v[5] = 0xFFFFFFFF;
    exp.v[6] = 0xFFFFFFFF;
    exp.v[7] = 0xFFFFFFFF;

    uint256 temp = *a;
    uint256 res;
    for (int i = 0; i < 8; ++i) res.v[i] = 0;
    res.v[0] = 1;

    for (int word = 0; word < 8; ++word) {
        uint32_t w = exp.v[word];
        for (int bit = 0; bit < 32; ++bit) {
            if (w & 1) {
                mod_mul(&res, &temp, &res);
            }
            mod_mul(&temp, &temp, &temp);
            w >>= 1;
        }
    }
    *r = res;
}

__device__ __forceinline__ void jacobian_double(const ec_point_jacobian* p1, ec_point_jacobian* r) {
    uint256 X1 = p1->x;
    uint256 Y1 = p1->y;
    uint256 Z1 = p1->z;

    uint256 Y1_sq, Y1_4;
    mod_mul(&Y1, &Y1, &Y1_sq);
    mod_mul(&Y1_sq, &Y1_sq, &Y1_4);

    uint256 X1_sq, M;
    mod_mul(&X1, &X1, &X1_sq);
    uint256 double_X1_sq;
    mod_add(&X1_sq, &X1_sq, &double_X1_sq);
    mod_add(&double_X1_sq, &X1_sq, &M);

    uint256 X1_Y1_sq, S;
    mod_mul(&X1, &Y1_sq, &X1_Y1_sq);
    uint256 double_X1_Y1_sq;
    mod_add(&X1_Y1_sq, &X1_Y1_sq, &double_X1_Y1_sq);
    mod_add(&double_X1_Y1_sq, &double_X1_Y1_sq, &S);

    uint256 T;
    uint256 double_Y1_4, quad_Y1_4;
    mod_add(&Y1_4, &Y1_4, &double_Y1_4);
    mod_add(&double_Y1_4, &double_Y1_4, &quad_Y1_4);
    mod_add(&quad_Y1_4, &quad_Y1_4, &T);

    uint256 M_sq, two_S, X3;
    mod_mul(&M, &M, &M_sq);
    mod_add(&S, &S, &two_S);
    mod_sub(&M_sq, &two_S, &X3);

    uint256 S_minus_X3, M_S_minus_X3, Y3;
    mod_sub(&S, &X3, &S_minus_X3);
    mod_mul(&M, &S_minus_X3, &M_S_minus_X3);
    mod_sub(&M_S_minus_X3, &T, &Y3);

    uint256 Y1_Z1, Z3;
    mod_mul(&Y1, &Z1, &Y1_Z1);
    mod_add(&Y1_Z1, &Y1_Z1, &Z3);

    r->x = X3;
    r->y = Y3;
    r->z = Z3;
}

__device__ __forceinline__ void jacobian_add_mixed(const ec_point_jacobian* p1, const ec_point_affine* p2, ec_point_jacobian* r) {
    uint256 X1 = p1->x;
    uint256 Y1 = p1->y;
    uint256 Z1 = p1->z;

    uint256 x2 = p2->x;
    uint256 y2 = p2->y;

    uint256 Z1_sq, Z1_cub;
    mod_mul(&Z1, &Z1, &Z1_sq);
    mod_mul(&Z1_sq, &Z1, &Z1_cub);

    uint256 U2;
    mod_mul(&x2, &Z1_sq, &U2);

    uint256 S2;
    mod_mul(&y2, &Z1_cub, &S2);

    uint256 H;
    mod_sub(&U2, &X1, &H);

    uint256 R;
    mod_sub(&S2, &Y1, &R);

    bool h_is_zero = true;
    for (int i = 0; i < 8; ++i) {
        if (H.v[i] != 0) { h_is_zero = false; break; }
    }
    if (h_is_zero) {
        bool r_is_zero = true;
        for (int i = 0; i < 8; ++i) {
            if (R.v[i] != 0) { r_is_zero = false; break; }
        }
        if (r_is_zero) {
            jacobian_double(p1, r);
        }
        else {
            for (int i = 0; i < 8; ++i) {
                r->x.v[i] = 0; r->y.v[i] = 0; r->z.v[i] = 0;
            }
        }
        return;
    }

    uint256 H_sq, H_cub;
    mod_mul(&H, &H, &H_sq);
    mod_mul(&H_sq, &H, &H_cub);

    uint256 U1_H_sq;
    mod_mul(&X1, &H_sq, &U1_H_sq);

    uint256 R_sq, two_U1_H_sq, X3;
    mod_mul(&R, &R, &R_sq);
    mod_add(&U1_H_sq, &U1_H_sq, &two_U1_H_sq);
    mod_sub(&R_sq, &H_cub, &X3);
    mod_sub(&X3, &two_U1_H_sq, &X3);

    uint256 U1_H_sq_minus_X3, R_diff, S1_H_cub, Y3;
    mod_sub(&U1_H_sq, &X3, &U1_H_sq_minus_X3);
    mod_mul(&R, &U1_H_sq_minus_X3, &R_diff);
    mod_mul(&Y1, &H_cub, &S1_H_cub);
    mod_sub(&R_diff, &S1_H_cub, &Y3);

    uint256 Z3;
    mod_mul(&Z1, &H, &Z3);

    r->x = X3;
    r->y = Y3;
    r->z = Z3;
}

__device__ __forceinline__ void scalar_multiply(const uint256* scalar, ec_point_affine* pub_key) {
    ec_point_affine G;
    G.x.v[0] = 0x16F81798; G.x.v[1] = 0x59F2815B; G.x.v[2] = 0x2DCE28D9; G.x.v[3] = 0x029BFCDB;
    G.x.v[4] = 0xCE870B07; G.x.v[5] = 0x55A06295; G.x.v[6] = 0xF9DCBBAC; G.x.v[7] = 0x79BE667E;

    G.y.v[0] = 0xFB10D4B8; G.y.v[1] = 0x9C47D08F; G.y.v[2] = 0xA6855419; G.y.v[3] = 0xFD17B448;
    G.y.v[4] = 0x0E1108A8; G.y.v[5] = 0x5DA4FBFC; G.y.v[6] = 0x26A3C465; G.y.v[7] = 0x483ADA77;

    ec_point_jacobian Q;
    Q.x = G.x;
    Q.y = G.y;
    for (int i = 0; i < 8; ++i) Q.z.v[i] = 0;
    Q.z.v[0] = 1;

    int msb = 255;
    while (msb >= 0) {
        int word = msb / 32;
        int bit = msb % 32;
        if ((scalar->v[word] >> bit) & 1) break;
        msb--;
    }

    if (msb < 0) {
        for (int i = 0; i < 8; ++i) {
            pub_key->x.v[i] = 0; pub_key->y.v[i] = 0;
        }
        return;
    }

    for (int i = msb - 1; i >= 0; --i) {
        jacobian_double(&Q, &Q);

        int word = i / 32;
        int bit = i % 32;
        if ((scalar->v[word] >> bit) & 1) {
            jacobian_add_mixed(&Q, &G, &Q);
        }
    }

    uint256 Z_inv, Z_inv_sq, Z_inv_cub;
    mod_inv(&Q.z, &Z_inv);
    mod_mul(&Z_inv, &Z_inv, &Z_inv_sq);
    mod_mul(&Z_inv_sq, &Z_inv, &Z_inv_cub);

    mod_mul(&Q.x, &Z_inv_sq, &pub_key->x);
    mod_mul(&Q.y, &Z_inv_cub, &pub_key->y);
}

// ==========================================
// SHA-256 IMPLEMENTATION
// ==========================================

__device__ const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

__device__ __forceinline__ void sha256_compress(uint32_t* state, const uint32_t* W) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    uint32_t w[16];
    for (int i = 0; i < 16; ++i) w[i] = W[i];

    for (int i = 0; i < 64; ++i) {
        uint32_t w_val;
        if (i < 16) {
            w_val = w[i];
        }
        else {
            w_val = sigma1(w[(i - 2) & 15]) + w[(i - 7) & 15] + sigma0(w[(i - 15) & 15]) + w[(i - 16) & 15];
            w[i & 15] = w_val;
        }
        uint32_t t1 = h + Sigma1(e) + Ch(e, f, g) + K256[i] + w_val;
        uint32_t t2 = Sigma0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

// ==========================================
// REGISTERS-DIRECT RIPEMD-160 (UNROLLED)
// ==========================================

__device__ __forceinline__ void ripemd160_compress(uint32_t* state, const uint32_t* X) {
    uint32_t al = state[0], bl = state[1], cl = state[2], dl = state[3], el = state[4];
    uint32_t ar = state[0], br = state[1], cr = state[2], dr = state[3], er = state[4];

    // --- LEFT LANE LANEWAY (80 Rounds) ---
    // Round 1 (0..15)
    FF(al, bl, cl, dl, el, X[0], 11);
    FF(el, al, bl, cl, dl, X[1], 14);
    FF(dl, el, al, bl, cl, X[2], 15);
    FF(cl, dl, el, al, bl, X[3], 12);
    FF(bl, cl, dl, el, al, X[4], 5);
    FF(al, bl, cl, dl, el, X[5], 8);
    FF(el, al, bl, cl, dl, X[6], 7);
    FF(dl, el, al, bl, cl, X[7], 9);
    FF(cl, dl, el, al, bl, X[8], 11);
    FF(bl, cl, dl, el, al, X[9], 13);
    FF(al, bl, cl, dl, el, X[10], 14);
    FF(el, al, bl, cl, dl, X[11], 15);
    FF(dl, el, al, bl, cl, X[12], 6);
    FF(cl, dl, el, al, bl, X[13], 7);
    FF(bl, cl, dl, el, al, X[14], 9);
    FF(al, bl, cl, dl, el, X[15], 8);

    // Round 2 (16..31)
    GG(el, al, bl, cl, dl, X[7], 7);
    GG(dl, el, al, bl, cl, X[4], 6);
    GG(cl, dl, el, al, bl, X[13], 8);
    GG(bl, cl, dl, el, al, X[1], 13);
    GG(al, bl, cl, dl, el, X[10], 11);
    GG(el, al, bl, cl, dl, X[6], 9);
    GG(dl, el, al, bl, cl, X[15], 7);
    GG(cl, dl, el, al, bl, X[3], 15);
    GG(bl, cl, dl, el, al, X[12], 7);
    GG(al, bl, cl, dl, el, X[0], 12);
    GG(el, al, bl, cl, dl, X[9], 15);
    GG(dl, el, al, bl, cl, X[5], 9);
    GG(cl, dl, el, al, bl, X[2], 11);
    GG(bl, cl, dl, el, al, X[14], 7);
    GG(al, bl, cl, dl, el, X[11], 13);
    GG(el, al, bl, cl, dl, X[8], 12);

    // Round 3 (32..47)
    HH(dl, el, al, bl, cl, X[3], 11);
    HH(cl, dl, el, al, bl, X[10], 13);
    HH(bl, cl, dl, el, al, X[14], 6);
    HH(al, bl, cl, dl, el, X[4], 7);
    HH(el, al, bl, cl, dl, X[9], 14);
    HH(dl, el, al, bl, cl, X[15], 9);
    HH(cl, dl, el, al, bl, X[8], 13);
    HH(bl, cl, dl, el, al, X[1], 15);
    HH(al, bl, cl, dl, el, X[2], 14);
    HH(el, al, bl, cl, dl, X[7], 8);
    HH(dl, el, al, bl, cl, X[0], 13);
    HH(cl, dl, el, al, bl, X[6], 6);
    HH(bl, cl, dl, el, al, X[13], 5);
    HH(al, bl, cl, dl, el, X[11], 12);
    HH(el, al, bl, cl, dl, X[5], 7);
    HH(dl, el, al, bl, cl, X[12], 5);

    // Round 4 (48..63)
    II(cl, dl, el, al, bl, X[1], 11);
    II(bl, cl, dl, el, al, X[9], 12);
    II(al, bl, cl, dl, el, X[11], 14);
    II(el, al, bl, cl, dl, X[10], 15);
    II(dl, el, al, bl, cl, X[0], 14);
    II(cl, dl, el, al, bl, X[8], 15);
    II(bl, cl, dl, el, al, X[12], 9);
    II(al, bl, cl, dl, el, X[4], 8);
    II(el, al, bl, cl, dl, X[13], 9);
    II(dl, el, al, bl, cl, X[3], 14);
    II(cl, dl, el, al, bl, X[7], 5);
    II(bl, cl, dl, el, al, X[15], 6);
    II(al, bl, cl, dl, el, X[14], 8);
    II(el, al, bl, cl, dl, X[5], 6);
    II(dl, el, al, bl, cl, X[6], 5);
    II(cl, dl, el, al, bl, X[2], 12);

    // Round 5 (64..79)
    JJ(bl, cl, dl, el, al, X[4], 9);
    JJ(al, bl, cl, dl, el, X[0], 15);
    JJ(el, al, bl, cl, dl, X[5], 5);
    JJ(dl, el, al, bl, cl, X[9], 11);
    JJ(cl, dl, el, al, bl, X[7], 6);
    JJ(bl, cl, dl, el, al, X[12], 8);
    JJ(al, bl, cl, dl, el, X[2], 13);
    JJ(el, al, bl, cl, dl, X[10], 12);
    JJ(dl, el, al, bl, cl, X[14], 5);
    JJ(cl, dl, el, al, bl, X[1], 12);
    JJ(bl, cl, dl, el, al, X[3], 13);
    JJ(al, bl, cl, dl, el, X[8], 14);
    JJ(el, al, bl, cl, dl, X[11], 11);
    JJ(dl, el, al, bl, cl, X[6], 8);
    JJ(cl, dl, el, al, bl, X[15], 5);
    JJ(bl, cl, dl, el, al, X[13], 6);

    // --- RIGHT LANE LANEWAY (80 Rounds) ---
    // Round 1 (0..15)
    FFF(ar, br, cr, dr, er, X[5], 8);
    FFF(er, ar, br, cr, dr, X[14], 9);
    FFF(dr, er, ar, br, cr, X[7], 9);
    FFF(cr, dr, er, ar, br, X[0], 11);
    FFF(br, cr, dr, er, ar, X[9], 13);
    FFF(ar, br, cr, dr, er, X[2], 15);
    FFF(er, ar, br, cr, dr, X[11], 15);
    FFF(dr, er, ar, br, cr, X[4], 5);
    FFF(cr, dr, er, ar, br, X[13], 7);
    FFF(br, cr, dr, er, ar, X[6], 7);
    FFF(ar, br, cr, dr, er, X[15], 8);
    FFF(er, ar, br, cr, dr, X[8], 11);
    FFF(dr, er, ar, br, cr, X[1], 14);
    FFF(cr, dr, er, ar, br, X[10], 14);
    FFF(br, cr, dr, er, ar, X[3], 12);
    FFF(ar, br, cr, dr, er, X[12], 6);

    // Round 2 (16..31)
    GGG(er, ar, br, cr, dr, X[6], 9);
    GGG(dr, er, ar, br, cr, X[11], 13);
    GGG(cr, dr, er, ar, br, X[3], 15);
    GGG(br, cr, dr, er, ar, X[7], 7);
    GGG(ar, br, cr, dr, er, X[0], 12);
    GGG(er, ar, br, cr, dr, X[13], 8);
    GGG(dr, er, ar, br, cr, X[5], 9);
    GGG(cr, dr, er, ar, br, X[10], 11);
    GGG(br, cr, dr, er, ar, X[14], 7);
    GGG(ar, br, cr, dr, er, X[15], 7);
    GGG(er, ar, br, cr, dr, X[8], 12);
    GGG(dr, er, ar, br, cr, X[12], 7);
    GGG(cr, dr, er, ar, br, X[4], 6);
    GGG(br, cr, dr, er, ar, X[9], 15);
    GGG(ar, br, cr, dr, er, X[1], 13);
    GGG(er, ar, br, cr, dr, X[2], 11);

    // Round 3 (32..47)
    HHH(dr, er, ar, br, cr, X[15], 9);
    HHH(cr, dr, er, ar, br, X[5], 7);
    HHH(br, cr, dr, er, ar, X[1], 15);
    HHH(ar, br, cr, dr, er, X[3], 11);
    HHH(er, ar, br, cr, dr, X[7], 8);
    HHH(dr, er, ar, br, cr, X[14], 6);
    HHH(cr, dr, er, ar, br, X[6], 6);
    HHH(br, cr, dr, er, ar, X[9], 14);
    HHH(ar, br, cr, dr, er, X[11], 12);
    HHH(er, ar, br, cr, dr, X[8], 13);
    HHH(dr, er, ar, br, cr, X[12], 5);
    HHH(cr, dr, er, ar, br, X[2], 14);
    HHH(br, cr, dr, er, ar, X[10], 13);
    HHH(ar, br, cr, dr, er, X[0], 13);
    HHH(er, ar, br, cr, dr, X[4], 7);
    HHH(dr, er, ar, br, cr, X[13], 5);

    // Round 4 (48..63)
    III(cr, dr, er, ar, br, X[8], 15);
    III(br, cr, dr, er, ar, X[6], 5);
    III(ar, br, cr, dr, er, X[4], 8);
    III(er, ar, br, cr, dr, X[1], 11);
    III(dr, er, ar, br, cr, X[3], 14);
    III(cr, dr, er, ar, br, X[11], 14);
    III(br, cr, dr, er, ar, X[15], 6);
    III(ar, br, cr, dr, er, X[0], 14);
    III(er, ar, br, cr, dr, X[5], 6);
    III(dr, er, ar, br, cr, X[12], 9);
    III(cr, dr, er, ar, br, X[2], 12);
    III(br, cr, dr, er, ar, X[13], 9);
    III(ar, br, cr, dr, er, X[9], 12);
    III(er, ar, br, cr, dr, X[7], 5);
    III(dr, er, ar, br, cr, X[10], 15);
    III(cr, dr, er, ar, br, X[14], 8);

    // Round 5 (64..79)
    JJJ(br, cr, dr, er, ar, X[12], 8);
    JJJ(ar, br, cr, dr, er, X[15], 5);
    JJJ(er, ar, br, cr, dr, X[10], 12);
    JJJ(dr, er, ar, br, cr, X[4], 9);
    JJJ(cr, dr, er, ar, br, X[1], 12);
    JJJ(br, cr, dr, er, ar, X[5], 5);
    JJJ(ar, br, cr, dr, er, X[8], 14);
    JJJ(er, ar, br, cr, dr, X[7], 6);
    JJJ(dr, er, ar, br, cr, X[6], 8);
    JJJ(cr, dr, er, ar, br, X[2], 13);
    JJJ(br, cr, dr, er, ar, X[13], 6);
    JJJ(ar, br, cr, dr, er, X[14], 5);
    JJJ(er, ar, br, cr, dr, X[0], 15);
    JJJ(dr, er, ar, br, cr, X[3], 13);
    JJJ(cr, dr, er, ar, br, X[9], 11);
    JJJ(br, cr, dr, er, ar, X[11], 11);

    // --- REGISTERS-DIRECT COMBINATION (FIXED MAPPING) ---
    uint32_t T = state[1] + cl + dr;   // state[1] + c + dd
    state[1] = state[2] + dl + er;     // state[2] + d + ee
    state[2] = state[3] + el + ar;     // state[3] + e + aa
    state[3] = state[4] + al + br;     // state[4] + a + bb
    state[4] = state[0] + bl + cr;     // state[0] + b + cc
    state[0] = T;
}

// ==========================================
// BYTE-SERIALIZATION & SHA-256 STREAM WRAPPERS
// ==========================================

__device__ __forceinline__ void serialize_pubkey_compressed(const ec_point_affine* pub, uint8_t out[33]) {
    out[0] = (pub->y.v[0] & 1) ? 0x03 : 0x02;
    for (int i = 0; i < 8; i++) {
        uint32_t v = pub->x.v[7 - i];
        out[1 + i * 4 + 0] = (v >> 24) & 0xFF;
        out[1 + i * 4 + 1] = (v >> 16) & 0xFF;
        out[1 + i * 4 + 2] = (v >> 8) & 0xFF;
        out[1 + i * 4 + 3] = v & 0xFF;
    }
}

__device__ __forceinline__ void serialize_pubkey_uncompressed(const ec_point_affine* pub, uint8_t out[65]) {
    out[0] = 0x04;
    for (int i = 0; i < 8; i++) {
        uint32_t vx = pub->x.v[7 - i];
        out[1 + i * 4 + 0] = (vx >> 24) & 0xFF;
        out[1 + i * 4 + 1] = (vx >> 16) & 0xFF;
        out[1 + i * 4 + 2] = (vx >> 8) & 0xFF;
        out[1 + i * 4 + 3] = vx & 0xFF;
    }
    for (int i = 0; i < 8; i++) {
        uint32_t vy = pub->y.v[7 - i];
        out[33 + i * 4 + 0] = (vy >> 24) & 0xFF;
        out[33 + i * 4 + 1] = (vy >> 16) & 0xFF;
        out[33 + i * 4 + 2] = (vy >> 8) & 0xFF;
        out[33 + i * 4 + 3] = vy & 0xFF;
    }
}

__device__ __forceinline__ void sha256_33bytes(const uint8_t* data, uint32_t* state) {
    uint32_t W[16] = { 0 };
    for (int i = 0; i < 33; ++i) {
        W[i / 4] |= (uint32_t)data[i] << (24 - (i % 4) * 8);
    }
    W[8] |= 0x00800000; // padding 0x80 byte at index 33
    W[15] = 264;        // size in bits: 33 * 8 = 264

    sha256_compress(state, W);
}

__device__ __forceinline__ void sha256_65bytes(const uint8_t* data, uint32_t* state) {
    // block 1 (first 64 bytes)
    uint32_t W1[16] = { 0 };
    for (int i = 0; i < 64; ++i) {
        W1[i / 4] |= (uint32_t)data[i] << (24 - (i % 4) * 8);
    }
    sha256_compress(state, W1);

    // block 2 (remaining 1 byte + padding)
    uint32_t W2[16] = { 0 };
    W2[0] = (uint32_t)data[64] << 24;
    W2[0] |= 0x00800000; // padding 0x80 byte at index 65
    W2[15] = 520;        // total size in bits: 65 * 8 = 520

    sha256_compress(state, W2);
}

__device__ __forceinline__ void sha256_22bytes(const uint8_t* data, uint32_t* state) {
    uint32_t W[16] = { 0 };
    for (int i = 0; i < 22; ++i) {
        W[i / 4] |= (uint32_t)data[i] << (24 - (i % 4) * 8);
    }
    W[5] |= 0x00008000; // padding 0x80 byte at index 22
    W[15] = 176;        // size in bits: 22 * 8 = 176

    sha256_compress(state, W);
}

__device__ __forceinline__ void ripemd160_sha256(const uint32_t* sha_state, uint8_t* out_hash) {
    uint32_t R_block[16] = { 0 };
    for (int i = 0; i < 8; ++i) {
        R_block[i] = swab32(sha_state[i]);
    }
    R_block[8] = 0x00000080;
    R_block[14] = 256;

    uint32_t ripemd_state[5] = {
        0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
    };
    ripemd160_compress(ripemd_state, R_block);

    for (int i = 0; i < 5; ++i) {
        out_hash[i * 4 + 0] = (uint8_t)(ripemd_state[i]);
        out_hash[i * 4 + 1] = (uint8_t)(ripemd_state[i] >> 8);
        out_hash[i * 4 + 2] = (uint8_t)(ripemd_state[i] >> 16);
        out_hash[i * 4 + 3] = (uint8_t)(ripemd_state[i] >> 24);
    }
}

// ==========================================
// DEDICATED HASH160 WRAPPER STEPS
// ==========================================

__device__ __forceinline__ void hash160_compressed(const ec_point_affine* pub, uint8_t* out_hash) {
    uint8_t pubser[33];
    serialize_pubkey_compressed(pub, pubser);

    uint32_t sha_state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    sha256_33bytes(pubser, sha_state);
    ripemd160_sha256(sha_state, out_hash);
}

__device__ __forceinline__ void hash160_uncompressed(const ec_point_affine* pub, uint8_t* out_hash) {
    uint8_t pubser[65];
    serialize_pubkey_uncompressed(pub, pubser);

    uint32_t sha_state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    sha256_65bytes(pubser, sha_state);
    ripemd160_sha256(sha_state, out_hash);
}

__device__ __forceinline__ void hash160_segwit(const uint8_t* compressed_hash, uint8_t* out_hash) {
    uint8_t redeem_script[22];
    redeem_script[0] = 0x00;
    redeem_script[1] = 0x14;
    for (int i = 0; i < 20; ++i) {
        redeem_script[2 + i] = compressed_hash[i];
    }

    uint32_t sha_state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    sha256_22bytes(redeem_script, sha_state);
    ripemd160_sha256(sha_state, out_hash);
}