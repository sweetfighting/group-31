#include "ghash.h"

#include <immintrin.h>
#include <string.h>

#if defined(__GNUC__) || defined(__clang__)
#define TARGET_PCLMUL __attribute__((target("pclmul,sse2")))
#else
#define TARGET_PCLMUL
#endif

static void xor_block(uint8_t x[16], const uint8_t y[16]) {
    for (unsigned i = 0; i < 16; ++i) x[i] ^= y[i];
}

/* Straightforward NIST SP 800-38D multiplication, MSB first. */
static void gf_mul_scalar(const uint8_t x[16], const uint8_t y[16], uint8_t out[16]) {
    uint8_t z[16] = {0};
    uint8_t v[16];
    memcpy(v, y, 16);
    for (unsigned i = 0; i < 128; ++i) {
        unsigned byte = i >> 3;
        unsigned bit = 7u - (i & 7u);
        if ((x[byte] >> bit) & 1u) xor_block(z, v);
        uint8_t lsb = (uint8_t)(v[15] & 1u);
        for (int j = 15; j > 0; --j)
            v[j] = (uint8_t)((v[j] >> 1) | (v[j-1] << 7));
        v[0] >>= 1;
        if (lsb) v[0] ^= 0xe1u;
    }
    memcpy(out, z, 16);
}

static uint8_t reverse_byte(uint8_t x) {
    x = (uint8_t)(((x & 0x55u) << 1) | ((x >> 1) & 0x55u));
    x = (uint8_t)(((x & 0x33u) << 2) | ((x >> 2) & 0x33u));
    x = (uint8_t)((x << 4) | (x >> 4));
    return x;
}

/* GHASH Algorithm 1 treats the leftmost bit as polynomial coefficient x^0.
   After a normal little-endian SIMD load, reversing the bits in each byte maps
   sequence bit i to CLMUL register bit i; the byte order itself is unchanged. */
static void ghash_to_clmul(const uint8_t in[16], uint8_t out[16]) {
    for (unsigned i = 0; i < 16; ++i) out[i] = reverse_byte(in[i]);
}

static void toggle_bit(uint64_t w[4], unsigned bit) {
    w[bit >> 6] ^= UINT64_C(1) << (bit & 63u);
}

TARGET_PCLMUL
static void gf_mul_pclmul(const uint8_t x_be[16], const uint8_t y_be[16], uint8_t out_be[16]) {
    uint8_t xr[16], yr[16], rr[16];
    ghash_to_clmul(x_be, xr);
    ghash_to_clmul(y_be, yr);
    __m128i a = _mm_loadu_si128((const __m128i *)xr);
    __m128i b = _mm_loadu_si128((const __m128i *)yr);
    __m128i p00 = _mm_clmulepi64_si128(a, b, 0x00);
    __m128i p01 = _mm_clmulepi64_si128(a, b, 0x10);
    __m128i p10 = _mm_clmulepi64_si128(a, b, 0x01);
    __m128i p11 = _mm_clmulepi64_si128(a, b, 0x11);
    __m128i cross = _mm_xor_si128(p01, p10);

    uint64_t a00[2], a11[2], ac[2], w[4];
    _mm_storeu_si128((__m128i *)a00, p00);
    _mm_storeu_si128((__m128i *)a11, p11);
    _mm_storeu_si128((__m128i *)ac, cross);
    w[0] = a00[0];
    w[1] = a00[1] ^ ac[0];
    w[2] = a11[0] ^ ac[1];
    w[3] = a11[1];

    /* Polynomial long division by x^128 + x^7 + x^2 + x + 1. */
    for (int bit = 255; bit >= 128; --bit) {
        if ((w[(unsigned)bit >> 6] >> ((unsigned)bit & 63u)) & UINT64_C(1)) {
            toggle_bit(w, (unsigned)bit);
            unsigned k = (unsigned)bit - 128u;
            toggle_bit(w, k + 7u);
            toggle_bit(w, k + 2u);
            toggle_bit(w, k + 1u);
            toggle_bit(w, k);
        }
    }
    memcpy(rr, w, 16);
    ghash_to_clmul(rr, out_be);
}

static void ghash_update(uint8_t y[16], const uint8_t h[16],
                         const uint8_t block[16], int use_pclmul) {
    uint8_t x[16];
    for (unsigned i = 0; i < 16; ++i) x[i] = (uint8_t)(y[i] ^ block[i]);
    if (use_pclmul) gf_mul_pclmul(x, h, y);
    else gf_mul_scalar(x, h, y);
}

static void process_padded(uint8_t y[16], const uint8_t h[16],
                           const uint8_t *data, size_t len, int use_pclmul) {
    while (len >= 16) {
        ghash_update(y, h, data, use_pclmul);
        data += 16;
        len -= 16;
    }
    if (len != 0) {
        uint8_t last[16] = {0};
        memcpy(last, data, len);
        ghash_update(y, h, last, use_pclmul);
    }
}

static void store_be64(uint8_t out[8], uint64_t x) {
    for (int i = 7; i >= 0; --i) {
        out[i] = (uint8_t)x;
        x >>= 8;
    }
}

void ghash_compute(const uint8_t h[16],
                   const uint8_t *aad, size_t aad_len,
                   const uint8_t *ciphertext, size_t ciphertext_len,
                   uint8_t out[16], int use_pclmul) {
    uint8_t y[16] = {0};
    if (aad_len) process_padded(y, h, aad, aad_len, use_pclmul);
    if (ciphertext_len) process_padded(y, h, ciphertext, ciphertext_len, use_pclmul);
    uint8_t lengths[16];
    store_be64(lengths, (uint64_t)aad_len * 8u);
    store_be64(lengths + 8, (uint64_t)ciphertext_len * 8u);
    ghash_update(y, h, lengths, use_pclmul);
    memcpy(out, y, 16);
}
