#ifndef GHASH_H
#define GHASH_H

#include <stddef.h>
#include <stdint.h>

void ghash_compute(const uint8_t h[16],
                   const uint8_t *aad, size_t aad_len,
                   const uint8_t *ciphertext, size_t ciphertext_len,
                   uint8_t out[16], int use_pclmul);

#endif
