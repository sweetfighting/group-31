#include "aes128.h"

#include <immintrin.h>

#if defined(__GNUC__) || defined(__clang__)
#define TARGET_AESNI __attribute__((target("aes,sse2")))
#define TARGET_VAES  __attribute__((target("vaes,avx2,aes")))
#else
#define TARGET_AESNI
#define TARGET_VAES
#endif

TARGET_AESNI
void aes128_encrypt_aesni(const aes128_ctx *ctx,
                          const uint8_t in[16], uint8_t out[16]) {
    __m128i x = _mm_loadu_si128((const __m128i *)in);
    x = _mm_xor_si128(x, _mm_loadu_si128((const __m128i *)ctx->round_keys[0]));
    for (unsigned r = 1; r < AES128_ROUNDS; ++r)
        x = _mm_aesenc_si128(x, _mm_loadu_si128((const __m128i *)ctx->round_keys[r]));
    x = _mm_aesenclast_si128(x, _mm_loadu_si128((const __m128i *)ctx->round_keys[10]));
    _mm_storeu_si128((__m128i *)out, x);
}

TARGET_AESNI
void aes128_decrypt_aesni(const aes128_ctx *ctx,
                          const uint8_t in[16], uint8_t out[16]) {
    __m128i x = _mm_loadu_si128((const __m128i *)in);
    x = _mm_xor_si128(x, _mm_loadu_si128((const __m128i *)ctx->round_keys[10]));
    for (int r = 9; r > 0; --r) {
        __m128i rk = _mm_loadu_si128((const __m128i *)ctx->round_keys[r]);
        x = _mm_aesdec_si128(x, _mm_aesimc_si128(rk));
    }
    x = _mm_aesdeclast_si128(x, _mm_loadu_si128((const __m128i *)ctx->round_keys[0]));
    _mm_storeu_si128((__m128i *)out, x);
}

TARGET_VAES
void aes128_encrypt2_vaes(const aes128_ctx *ctx,
                          const uint8_t in[32], uint8_t out[32]) {
    __m256i x = _mm256_loadu_si256((const __m256i *)in);
    __m128i r0 = _mm_loadu_si128((const __m128i *)ctx->round_keys[0]);
    x = _mm256_xor_si256(x, _mm256_broadcastsi128_si256(r0));
    for (unsigned r = 1; r < AES128_ROUNDS; ++r) {
        __m128i rk128 = _mm_loadu_si128((const __m128i *)ctx->round_keys[r]);
        __m256i rk = _mm256_broadcastsi128_si256(rk128);
        x = _mm256_aesenc_epi128(x, rk);
    }
    __m128i rk128 = _mm_loadu_si128((const __m128i *)ctx->round_keys[10]);
    x = _mm256_aesenclast_epi128(x, _mm256_broadcastsi128_si256(rk128));
    _mm256_storeu_si256((__m256i *)out, x);
}

TARGET_VAES
void aes128_decrypt2_vaes(const aes128_ctx *ctx,
                          const uint8_t in[32], uint8_t out[32]) {
    __m256i x = _mm256_loadu_si256((const __m256i *)in);
    __m128i r10 = _mm_loadu_si128((const __m128i *)ctx->round_keys[10]);
    x = _mm256_xor_si256(x, _mm256_broadcastsi128_si256(r10));
    for (int r = 9; r > 0; --r) {
        __m128i rk128 = _mm_loadu_si128((const __m128i *)ctx->round_keys[r]);
        rk128 = _mm_aesimc_si128(rk128);
        x = _mm256_aesdec_epi128(x, _mm256_broadcastsi128_si256(rk128));
    }
    __m128i r0 = _mm_loadu_si128((const __m128i *)ctx->round_keys[0]);
    x = _mm256_aesdeclast_epi128(x, _mm256_broadcastsi128_si256(r0));
    _mm256_storeu_si256((__m256i *)out, x);
}
