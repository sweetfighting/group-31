#ifndef AES128_H
#define AES128_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AES128_BLOCK_SIZE 16u
#define AES128_ROUNDS 10u
#define AES128_ROUND_KEYS 11u

typedef enum {
    AES_BACKEND_REFERENCE = 0,
    AES_BACKEND_TTABLE,
    AES_BACKEND_SHUFFLE,
    AES_BACKEND_AESNI,
    AES_BACKEND_VAES
} aes_backend;

typedef struct {
    /* 11 round keys, each 16 bytes, in AES column-major byte order. */
    uint8_t round_keys[AES128_ROUND_KEYS][AES128_BLOCK_SIZE];
} aes128_ctx;

typedef struct {
    int ssse3;
    int aesni;
    int pclmul;
    int avx2;
    int vaes;
} aes_cpu_features;

void aes128_init(aes128_ctx *ctx, const uint8_t key[16]);

void aes128_encrypt_reference(const aes128_ctx *ctx,
                              const uint8_t in[16], uint8_t out[16]);
void aes128_decrypt_reference(const aes128_ctx *ctx,
                              const uint8_t in[16], uint8_t out[16]);

void aes128_encrypt_ttable(const aes128_ctx *ctx,
                           const uint8_t in[16], uint8_t out[16]);
void aes128_decrypt_ttable(const aes128_ctx *ctx,
                           const uint8_t in[16], uint8_t out[16]);

void aes128_encrypt_shuffle(const aes128_ctx *ctx,
                            const uint8_t in[16], uint8_t out[16]);
void aes128_decrypt_shuffle(const aes128_ctx *ctx,
                            const uint8_t in[16], uint8_t out[16]);

void aes128_encrypt_aesni(const aes128_ctx *ctx,
                          const uint8_t in[16], uint8_t out[16]);
void aes128_decrypt_aesni(const aes128_ctx *ctx,
                          const uint8_t in[16], uint8_t out[16]);

/* VAES works on two independent 128-bit lanes at once. */
void aes128_encrypt2_vaes(const aes128_ctx *ctx,
                          const uint8_t in[32], uint8_t out[32]);
void aes128_decrypt2_vaes(const aes128_ctx *ctx,
                          const uint8_t in[32], uint8_t out[32]);

void aes128_encrypt_block(const aes128_ctx *ctx, aes_backend backend,
                          const uint8_t in[16], uint8_t out[16]);
void aes128_decrypt_block(const aes128_ctx *ctx, aes_backend backend,
                          const uint8_t in[16], uint8_t out[16]);

const char *aes_backend_name(aes_backend backend);
aes_cpu_features aes_detect_cpu_features(void);
int aes_backend_is_supported(aes_backend backend, aes_cpu_features f);

#ifdef __cplusplus
}
#endif

#endif
