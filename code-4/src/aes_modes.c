#include "aes_modes.h"
#include "ghash.h"

#include <string.h>

static void inc32(uint8_t counter[16]) {
    for (int i = 15; i >= 12; --i) {
        counter[i] = (uint8_t)(counter[i] + 1u);
        if (counter[i] != 0) break;
    }
}

static void xor16(uint8_t out[16], const uint8_t a[16], const uint8_t b[16]) {
    for (unsigned i = 0; i < 16; ++i) out[i] = (uint8_t)(a[i] ^ b[i]);
}

void aes128_ctr_crypt(const aes128_ctx *ctx, aes_backend backend,
                      const uint8_t initial_counter[16],
                      const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t counter[16];
    memcpy(counter, initial_counter, 16);

    if (backend == AES_BACKEND_VAES) {
        while (len >= 32) {
            uint8_t counters[32], stream[32];
            memcpy(counters, counter, 16);
            inc32(counter);
            memcpy(counters + 16, counter, 16);
            inc32(counter);
            aes128_encrypt2_vaes(ctx, counters, stream);
            for (unsigned i = 0; i < 32; ++i) out[i] = (uint8_t)(in[i] ^ stream[i]);
            in += 32; out += 32; len -= 32;
        }
    }

    while (len != 0) {
        uint8_t stream[16];
        aes128_encrypt_block(ctx, backend, counter, stream);
        size_t take = len < 16 ? len : 16;
        for (size_t i = 0; i < take; ++i) out[i] = (uint8_t)(in[i] ^ stream[i]);
        in += take; out += take; len -= take;
        inc32(counter);
    }
}

void aes128_gcm_encrypt(const aes128_ctx *ctx, aes_backend backend,
                        const uint8_t iv[12],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *plaintext, size_t plaintext_len,
                        uint8_t *ciphertext, uint8_t tag[16],
                        int use_pclmul) {
    uint8_t zero[16] = {0}, h[16], j0[16] = {0}, counter[16], s[16], ej0[16];
    aes128_encrypt_block(ctx, backend, zero, h);
    memcpy(j0, iv, 12);
    j0[15] = 1;
    memcpy(counter, j0, 16);
    inc32(counter);
    aes128_ctr_crypt(ctx, backend, counter, plaintext, ciphertext, plaintext_len);
    ghash_compute(h, aad, aad_len, ciphertext, plaintext_len, s, use_pclmul);
    aes128_encrypt_block(ctx, backend, j0, ej0);
    xor16(tag, ej0, s);
}

static int constant_time_equal_16(const uint8_t a[16], const uint8_t b[16]) {
    uint8_t d = 0;
    for (unsigned i = 0; i < 16; ++i) d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}

int aes128_gcm_decrypt(const aes128_ctx *ctx, aes_backend backend,
                       const uint8_t iv[12],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ciphertext, size_t ciphertext_len,
                       const uint8_t tag[16], uint8_t *plaintext,
                       int use_pclmul) {
    uint8_t zero[16] = {0}, h[16], j0[16] = {0}, counter[16], s[16], ej0[16], expected[16];
    aes128_encrypt_block(ctx, backend, zero, h);
    memcpy(j0, iv, 12);
    j0[15] = 1;
    ghash_compute(h, aad, aad_len, ciphertext, ciphertext_len, s, use_pclmul);
    aes128_encrypt_block(ctx, backend, j0, ej0);
    xor16(expected, ej0, s);
    if (!constant_time_equal_16(expected, tag)) {
        if (plaintext && ciphertext_len) memset(plaintext, 0, ciphertext_len);
        return 0;
    }
    memcpy(counter, j0, 16);
    inc32(counter);
    aes128_ctr_crypt(ctx, backend, counter, ciphertext, plaintext, ciphertext_len);
    return 1;
}

static void xts_mul_alpha(uint8_t tweak[16]) {
    uint8_t carry = 0;
    for (unsigned i = 0; i < 16; ++i) {
        uint8_t next = (uint8_t)(tweak[i] >> 7);
        tweak[i] = (uint8_t)((tweak[i] << 1) | carry);
        carry = next;
    }
    if (carry) tweak[0] ^= 0x87u;
}

static void xts_crypt_one(const aes128_ctx *data_ctx, aes_backend backend,
                          const uint8_t tweak[16], const uint8_t in[16],
                          uint8_t out[16], int decrypt) {
    uint8_t x[16], y[16];
    xor16(x, in, tweak);
    if (decrypt) aes128_decrypt_block(data_ctx, backend, x, y);
    else aes128_encrypt_block(data_ctx, backend, x, y);
    xor16(out, y, tweak);
}

static void xts_crypt_full_blocks(const aes128_ctx *data_ctx, aes_backend backend,
                                  uint8_t tweak[16], const uint8_t *in,
                                  uint8_t *out, size_t blocks, int decrypt) {
    if (backend == AES_BACKEND_VAES) {
        while (blocks >= 2) {
            uint8_t tweaks[32], x[32], y[32];
            memcpy(tweaks, tweak, 16);
            xts_mul_alpha(tweak);
            memcpy(tweaks + 16, tweak, 16);
            xts_mul_alpha(tweak);
            for (unsigned i = 0; i < 32; ++i) x[i] = (uint8_t)(in[i] ^ tweaks[i]);
            if (decrypt) aes128_decrypt2_vaes(data_ctx, x, y);
            else aes128_encrypt2_vaes(data_ctx, x, y);
            for (unsigned i = 0; i < 32; ++i) out[i] = (uint8_t)(y[i] ^ tweaks[i]);
            in += 32; out += 32; blocks -= 2;
        }
    }
    while (blocks--) {
        xts_crypt_one(data_ctx, backend, tweak, in, out, decrypt);
        xts_mul_alpha(tweak);
        in += 16; out += 16;
    }
}

int aes128_xts_encrypt(const aes128_ctx *data_ctx,
                       const aes128_ctx *tweak_ctx,
                       aes_backend backend,
                       const uint8_t data_unit_number[16],
                       const uint8_t *plaintext, uint8_t *ciphertext,
                       size_t len) {
    if (len < 16) return 0;
    uint8_t tweak[16];
    aes128_encrypt_block(tweak_ctx, backend, data_unit_number, tweak);
    size_t full = len / 16;
    size_t rem = len % 16;
    if (rem == 0) {
        xts_crypt_full_blocks(data_ctx, backend, tweak, plaintext, ciphertext, full, 0);
        return 1;
    }

    if (full > 1) {
        xts_crypt_full_blocks(data_ctx, backend, tweak, plaintext, ciphertext, full - 1, 0);
        plaintext += 16 * (full - 1);
        ciphertext += 16 * (full - 1);
    }

    uint8_t cc[16], pp[16], tweak_next[16];
    xts_crypt_one(data_ctx, backend, tweak, plaintext, cc, 0);
    memcpy(ciphertext + 16, cc, rem);
    memcpy(pp, plaintext + 16, rem);
    memcpy(pp + rem, cc + rem, 16 - rem);
    memcpy(tweak_next, tweak, 16);
    xts_mul_alpha(tweak_next);
    xts_crypt_one(data_ctx, backend, tweak_next, pp, ciphertext, 0);
    return 1;
}

int aes128_xts_decrypt(const aes128_ctx *data_ctx,
                       const aes128_ctx *tweak_ctx,
                       aes_backend backend,
                       const uint8_t data_unit_number[16],
                       const uint8_t *ciphertext, uint8_t *plaintext,
                       size_t len) {
    if (len < 16) return 0;
    uint8_t tweak[16];
    aes128_encrypt_block(tweak_ctx, backend, data_unit_number, tweak);
    size_t full = len / 16;
    size_t rem = len % 16;
    if (rem == 0) {
        xts_crypt_full_blocks(data_ctx, backend, tweak, ciphertext, plaintext, full, 1);
        return 1;
    }

    if (full > 1) {
        xts_crypt_full_blocks(data_ctx, backend, tweak, ciphertext, plaintext, full - 1, 1);
        ciphertext += 16 * (full - 1);
        plaintext += 16 * (full - 1);
    }

    uint8_t pp[16], cc[16], tweak_next[16];
    memcpy(tweak_next, tweak, 16);
    xts_mul_alpha(tweak_next);
    xts_crypt_one(data_ctx, backend, tweak_next, ciphertext, pp, 1);
    memcpy(plaintext + 16, pp, rem);
    memcpy(cc, ciphertext + 16, rem);
    memcpy(cc + rem, pp + rem, 16 - rem);
    xts_crypt_one(data_ctx, backend, tweak, cc, plaintext, 1);
    return 1;
}
