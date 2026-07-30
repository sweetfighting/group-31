#include "aes128.h"
#include "aes_internal.h"

#include <stdint.h>

static uint32_t te[4][256];
static uint32_t td[4][256];
static int tables_ready = 0;

static uint32_t pack_be(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return ((uint32_t)a << 24) | ((uint32_t)b << 16) |
           ((uint32_t)c << 8) | (uint32_t)d;
}

static uint32_t load_be32(const uint8_t *p) {
    return pack_be(p[0], p[1], p[2], p[3]);
}

static void store_be32(uint8_t *p, uint32_t x) {
    p[0] = (uint8_t)(x >> 24);
    p[1] = (uint8_t)(x >> 16);
    p[2] = (uint8_t)(x >> 8);
    p[3] = (uint8_t)x;
}

static void init_tables(void) {
    if (tables_ready) return;
    const uint8_t *s = aes_internal_sbox();
    const uint8_t *is = aes_internal_inv_sbox();
    for (unsigned x = 0; x < 256; ++x) {
        uint8_t y = s[x];
        uint8_t y2 = aes_internal_gmul(y, 2);
        uint8_t y3 = aes_internal_gmul(y, 3);
        te[0][x] = pack_be(y2, y,  y,  y3);
        te[1][x] = pack_be(y3, y2, y,  y );
        te[2][x] = pack_be(y,  y3, y2, y );
        te[3][x] = pack_be(y,  y,  y3, y2);

        y = is[x];
        uint8_t y9  = aes_internal_gmul(y, 9);
        uint8_t y11 = aes_internal_gmul(y, 11);
        uint8_t y13 = aes_internal_gmul(y, 13);
        uint8_t y14 = aes_internal_gmul(y, 14);
        td[0][x] = pack_be(y14, y9,  y13, y11);
        td[1][x] = pack_be(y11, y14, y9,  y13);
        td[2][x] = pack_be(y13, y11, y14, y9 );
        td[3][x] = pack_be(y9,  y13, y11, y14);
    }
    tables_ready = 1;
}

static uint32_t inv_mix_key_word(const uint8_t *p) {
    uint8_t a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
    return pack_be(
        (uint8_t)(aes_internal_gmul(a0,14) ^ aes_internal_gmul(a1,11) ^
                  aes_internal_gmul(a2,13) ^ aes_internal_gmul(a3,9)),
        (uint8_t)(aes_internal_gmul(a0,9) ^ aes_internal_gmul(a1,14) ^
                  aes_internal_gmul(a2,11) ^ aes_internal_gmul(a3,13)),
        (uint8_t)(aes_internal_gmul(a0,13) ^ aes_internal_gmul(a1,9) ^
                  aes_internal_gmul(a2,14) ^ aes_internal_gmul(a3,11)),
        (uint8_t)(aes_internal_gmul(a0,11) ^ aes_internal_gmul(a1,13) ^
                  aes_internal_gmul(a2,9) ^ aes_internal_gmul(a3,14))
    );
}

void aes128_encrypt_ttable(const aes128_ctx *ctx,
                           const uint8_t in[16], uint8_t out[16]) {
    init_tables();
    uint8_t s[16], t[16];
    for (unsigned i = 0; i < 16; ++i) s[i] = (uint8_t)(in[i] ^ ctx->round_keys[0][i]);

    for (unsigned round = 1; round < AES128_ROUNDS; ++round) {
        for (unsigned c = 0; c < 4; ++c) {
            uint32_t w = te[0][s[4*c + 0]] ^
                         te[1][s[4*((c + 1) & 3u) + 1]] ^
                         te[2][s[4*((c + 2) & 3u) + 2]] ^
                         te[3][s[4*((c + 3) & 3u) + 3]] ^
                         load_be32(&ctx->round_keys[round][4*c]);
            store_be32(&t[4*c], w);
        }
        for (unsigned i = 0; i < 16; ++i) s[i] = t[i];
    }

    const uint8_t *sb = aes_internal_sbox();
    for (unsigned c = 0; c < 4; ++c) {
        t[4*c + 0] = (uint8_t)(sb[s[4*c + 0]] ^ ctx->round_keys[10][4*c + 0]);
        t[4*c + 1] = (uint8_t)(sb[s[4*((c + 1) & 3u) + 1]] ^ ctx->round_keys[10][4*c + 1]);
        t[4*c + 2] = (uint8_t)(sb[s[4*((c + 2) & 3u) + 2]] ^ ctx->round_keys[10][4*c + 2]);
        t[4*c + 3] = (uint8_t)(sb[s[4*((c + 3) & 3u) + 3]] ^ ctx->round_keys[10][4*c + 3]);
    }
    for (unsigned i = 0; i < 16; ++i) out[i] = t[i];
}

void aes128_decrypt_ttable(const aes128_ctx *ctx,
                           const uint8_t in[16], uint8_t out[16]) {
    init_tables();
    uint8_t s[16], t[16];
    for (unsigned i = 0; i < 16; ++i) s[i] = (uint8_t)(in[i] ^ ctx->round_keys[10][i]);

    for (int round = 9; round > 0; --round) {
        for (unsigned c = 0; c < 4; ++c) {
            uint32_t w = td[0][s[4*c + 0]] ^
                         td[1][s[4*((c + 3) & 3u) + 1]] ^
                         td[2][s[4*((c + 2) & 3u) + 2]] ^
                         td[3][s[4*((c + 1) & 3u) + 3]] ^
                         inv_mix_key_word(&ctx->round_keys[round][4*c]);
            store_be32(&t[4*c], w);
        }
        for (unsigned i = 0; i < 16; ++i) s[i] = t[i];
    }

    const uint8_t *isb = aes_internal_inv_sbox();
    for (unsigned c = 0; c < 4; ++c) {
        t[4*c + 0] = (uint8_t)(isb[s[4*c + 0]] ^ ctx->round_keys[0][4*c + 0]);
        t[4*c + 1] = (uint8_t)(isb[s[4*((c + 3) & 3u) + 1]] ^ ctx->round_keys[0][4*c + 1]);
        t[4*c + 2] = (uint8_t)(isb[s[4*((c + 2) & 3u) + 2]] ^ ctx->round_keys[0][4*c + 2]);
        t[4*c + 3] = (uint8_t)(isb[s[4*((c + 1) & 3u) + 3]] ^ ctx->round_keys[0][4*c + 3]);
    }
    for (unsigned i = 0; i < 16; ++i) out[i] = t[i];
}
