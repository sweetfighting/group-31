#ifndef AES_MODES_H
#define AES_MODES_H

#include "aes128.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* CTR uses a 128-bit big-endian counter and increments the low 32 bits. */
void aes128_ctr_crypt(const aes128_ctx *ctx, aes_backend backend,
                      const uint8_t initial_counter[16],
                      const uint8_t *in, uint8_t *out, size_t len);

/* GCM implementation for the common 96-bit IV case, 128-bit tag. */
void aes128_gcm_encrypt(const aes128_ctx *ctx, aes_backend backend,
                        const uint8_t iv[12],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *plaintext, size_t plaintext_len,
                        uint8_t *ciphertext, uint8_t tag[16],
                        int use_pclmul);

int aes128_gcm_decrypt(const aes128_ctx *ctx, aes_backend backend,
                       const uint8_t iv[12],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ciphertext, size_t ciphertext_len,
                       const uint8_t tag[16], uint8_t *plaintext,
                       int use_pclmul);

/* XTS supports arbitrary data-unit lengths >= 16 bytes, including CTS. */
int aes128_xts_encrypt(const aes128_ctx *data_ctx,
                       const aes128_ctx *tweak_ctx,
                       aes_backend backend,
                       const uint8_t data_unit_number[16],
                       const uint8_t *plaintext, uint8_t *ciphertext,
                       size_t len);

int aes128_xts_decrypt(const aes128_ctx *data_ctx,
                       const aes128_ctx *tweak_ctx,
                       aes_backend backend,
                       const uint8_t data_unit_number[16],
                       const uint8_t *ciphertext, uint8_t *plaintext,
                       size_t len);

#ifdef __cplusplus
}
#endif

#endif
