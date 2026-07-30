#include "aes128.h"

#if defined(__GNUC__) || defined(__clang__)
#include <cpuid.h>
#endif

const char *aes_backend_name(aes_backend backend) {
    switch (backend) {
        case AES_BACKEND_REFERENCE: return "reference";
        case AES_BACKEND_TTABLE:    return "t-table";
        case AES_BACKEND_SHUFFLE:   return "shuffle-ssse3";
        case AES_BACKEND_AESNI:     return "aes-ni";
        case AES_BACKEND_VAES:      return "vaes-256";
        default:                    return "unknown";
    }
}

aes_cpu_features aes_detect_cpu_features(void) {
    aes_cpu_features f = {0,0,0,0,0};
#if defined(__GNUC__) || defined(__clang__)
    __builtin_cpu_init();
    f.ssse3  = __builtin_cpu_supports("ssse3") != 0;
    f.aesni  = __builtin_cpu_supports("aes") != 0;
    f.pclmul = __builtin_cpu_supports("pclmul") != 0;
    f.avx2   = __builtin_cpu_supports("avx2") != 0;
    f.vaes   = __builtin_cpu_supports("vaes") != 0;
#endif
    return f;
}

int aes_backend_is_supported(aes_backend backend, aes_cpu_features f) {
    switch (backend) {
        case AES_BACKEND_REFERENCE:
        case AES_BACKEND_TTABLE:  return 1;
        case AES_BACKEND_SHUFFLE: return f.ssse3;
        case AES_BACKEND_AESNI:   return f.aesni;
        case AES_BACKEND_VAES:    return f.aesni && f.avx2 && f.vaes;
        default:                  return 0;
    }
}

void aes128_encrypt_block(const aes128_ctx *ctx, aes_backend backend,
                          const uint8_t in[16], uint8_t out[16]) {
    switch (backend) {
        case AES_BACKEND_REFERENCE: aes128_encrypt_reference(ctx,in,out); break;
        case AES_BACKEND_TTABLE:    aes128_encrypt_ttable(ctx,in,out); break;
        case AES_BACKEND_SHUFFLE:   aes128_encrypt_shuffle(ctx,in,out); break;
        case AES_BACKEND_AESNI:     aes128_encrypt_aesni(ctx,in,out); break;
        case AES_BACKEND_VAES:
            /* Single-block fallback; bulk mode code uses the real two-lane VAES path. */
            aes128_encrypt_aesni(ctx,in,out); break;
        default:                    aes128_encrypt_reference(ctx,in,out); break;
    }
}

void aes128_decrypt_block(const aes128_ctx *ctx, aes_backend backend,
                          const uint8_t in[16], uint8_t out[16]) {
    switch (backend) {
        case AES_BACKEND_REFERENCE: aes128_decrypt_reference(ctx,in,out); break;
        case AES_BACKEND_TTABLE:    aes128_decrypt_ttable(ctx,in,out); break;
        case AES_BACKEND_SHUFFLE:   aes128_decrypt_shuffle(ctx,in,out); break;
        case AES_BACKEND_AESNI:     aes128_decrypt_aesni(ctx,in,out); break;
        case AES_BACKEND_VAES:      aes128_decrypt_aesni(ctx,in,out); break;
        default:                    aes128_decrypt_reference(ctx,in,out); break;
    }
}
