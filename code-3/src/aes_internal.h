#ifndef AES_INTERNAL_H
#define AES_INTERNAL_H
#include <stdint.h>
const uint8_t *aes_internal_sbox(void);
const uint8_t *aes_internal_inv_sbox(void);
uint8_t aes_internal_gmul(uint8_t a, uint8_t b);
#endif
