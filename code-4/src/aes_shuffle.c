#include "aes128.h"
#include "aes_internal.h"

#include <string.h>
#include <tmmintrin.h>

#if defined(__GNUC__) || defined(__clang__)
#define TARGET_SSSE3 __attribute__((target("ssse3")))
#else
#define TARGET_SSSE3
#endif

static void sub_bytes_local(uint8_t s[16], int inverse) {
    const uint8_t *box = inverse ? aes_internal_inv_sbox() : aes_internal_sbox();
    for (unsigned i = 0; i < 16; ++i) s[i] = box[s[i]];
}

static uint8_t xtime_local(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1b));
}

static void mix_columns_local(uint8_t s[16], int inverse) {
    for (unsigned c = 0; c < 4; ++c) {
        uint8_t *a = &s[4*c];
        if (inverse) {
            uint8_t u = xtime_local(xtime_local((uint8_t)(a[0] ^ a[2])));
            uint8_t v = xtime_local(xtime_local((uint8_t)(a[1] ^ a[3])));
            a[0] ^= u; a[1] ^= v; a[2] ^= u; a[3] ^= v;
        }
        uint8_t x0=a[0], x1=a[1], x2=a[2], x3=a[3];
        uint8_t all=(uint8_t)(x0^x1^x2^x3);
        a[0]=(uint8_t)(x0 ^ all ^ xtime_local((uint8_t)(x0^x1)));
        a[1]=(uint8_t)(x1 ^ all ^ xtime_local((uint8_t)(x1^x2)));
        a[2]=(uint8_t)(x2 ^ all ^ xtime_local((uint8_t)(x2^x3)));
        a[3]=(uint8_t)(x3 ^ all ^ xtime_local((uint8_t)(x3^x0)));
    }
}

TARGET_SSSE3
void aes128_encrypt_shuffle(const aes128_ctx *ctx,
                            const uint8_t in[16], uint8_t out[16]) {
    static const uint8_t mask_bytes[16] = {
        0,5,10,15, 4,9,14,3, 8,13,2,7, 12,1,6,11
    };
    __m128i mask = _mm_loadu_si128((const __m128i *)mask_bytes);
    uint8_t s[16];
    for (unsigned i=0;i<16;++i) s[i]=(uint8_t)(in[i]^ctx->round_keys[0][i]);
    for (unsigned round=1; round<10; ++round) {
        sub_bytes_local(s,0);
        __m128i v=_mm_loadu_si128((const __m128i *)s);
        v=_mm_shuffle_epi8(v,mask);
        _mm_storeu_si128((__m128i *)s,v);
        mix_columns_local(s,0);
        for (unsigned i=0;i<16;++i) s[i]^=ctx->round_keys[round][i];
    }
    sub_bytes_local(s,0);
    __m128i v=_mm_loadu_si128((const __m128i *)s);
    v=_mm_shuffle_epi8(v,mask);
    _mm_storeu_si128((__m128i *)s,v);
    for (unsigned i=0;i<16;++i) out[i]=(uint8_t)(s[i]^ctx->round_keys[10][i]);
}

TARGET_SSSE3
void aes128_decrypt_shuffle(const aes128_ctx *ctx,
                            const uint8_t in[16], uint8_t out[16]) {
    static const uint8_t mask_bytes[16] = {
        0,13,10,7, 4,1,14,11, 8,5,2,15, 12,9,6,3
    };
    __m128i mask = _mm_loadu_si128((const __m128i *)mask_bytes);
    uint8_t s[16];
    for (unsigned i=0;i<16;++i) s[i]=(uint8_t)(in[i]^ctx->round_keys[10][i]);
    for (int round=9; round>0; --round) {
        __m128i v=_mm_loadu_si128((const __m128i *)s);
        v=_mm_shuffle_epi8(v,mask);
        _mm_storeu_si128((__m128i *)s,v);
        sub_bytes_local(s,1);
        for (unsigned i=0;i<16;++i) s[i]^=ctx->round_keys[round][i];
        mix_columns_local(s,1);
    }
    __m128i v=_mm_loadu_si128((const __m128i *)s);
    v=_mm_shuffle_epi8(v,mask);
    _mm_storeu_si128((__m128i *)s,v);
    sub_bytes_local(s,1);
    for (unsigned i=0;i<16;++i) out[i]=(uint8_t)(s[i]^ctx->round_keys[0][i]);
}
