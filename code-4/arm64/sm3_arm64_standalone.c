#include <string.h>
#include <stdint.h>
#include <arm_neon.h>

#define ROL32(x,n) (((x) << (n)) | ((x) >> (32-(n))))
#define P0(x) ((x) ^ ROL32((x), 9) ^ ROL32((x),17))
#define P1(x) ((x) ^ ROL32((x),15) ^ ROL32((x),23))
#define FF00(x,y,z) ((x) ^ (y) ^ (z))
#define FF16(x,y,z) (((x)&(y)) | ((x)&(z)) | ((y)&(z)))
#define GG00(x,y,z) ((x) ^ (y) ^ (z))
#define GG16(x,y,z) ((((y)^(z)) & (x)) ^ (z))

static const uint32_t K[64] = {
    0x79cc4519U,0xf3988a32U,0xe7311465U,0xce6228cbU,
    0x9cc45197U,0x3988a32fU,0x7311465eU,0xe6228cbcU,
    0xcc451979U,0x988a32f3U,0x311465e7U,0x6228cbceU,
    0xc451979cU,0x88a32f39U,0x11465e73U,0x228cbce6U,
    0x9d8a7a87U,0x3b14f50fU,0x7629ea1eU,0xec53d43cU,
    0xd8a7a879U,0xb14f50f3U,0x629ea1e7U,0xc53d43ceU,
    0x8a7a879dU,0x14f50f3bU,0x29ea1e76U,0x53d43cecU,
    0xa7a879d8U,0x4f50f3b1U,0x9ea1e762U,0x3d43cec5U,
    0x7a879d8aU,0xf50f3b14U,0xea1e7629U,0xd43cec53U,
    0xa879d8a7U,0x50f3b14fU,0xa1e7629eU,0x43cec53dU,
    0x879d8a7aU,0x0f3b14f5U,0x1e7629eaU,0x3cec53d4U,
    0x79d8a7a8U,0xf3b14f50U,0xe7629ea1U,0xcec53d43U,
    0x9d8a7a87U,0x3b14f50fU,0x7629ea1eU,0xec53d43cU,
    0xd8a7a879U,0xb14f50f3U,0x629ea1e7U,0xc53d43ceU,
    0x8a7a879dU,0x14f50f3bU,0x29ea1e76U,0x53d43cecU,
    0xa7a879d8U,0x4f50f3b1U,0x9ea1e762U,0x3d43cec5U,
};

static inline uint32_t GETU32(const uint8_t *p) {
    return ((uint32_t)p[0]<<24) | ((uint32_t)p[1]<<16) | ((uint32_t)p[2]<<8) | p[3];
}

static inline uint32x4_t ROL32_NEON(uint32x4_t x, int n) {
    return vorrq_u32(vshlq_n_u32(x, n), vshrq_n_u32(x, 32 - n));
}
static inline uint32x4_t P1_NEON(uint32x4_t x) {
    return veorq_u32(veorq_u32(x, ROL32_NEON(x, 15)), ROL32_NEON(x, 23));
}
static inline uint32x4_t P0_NEON(uint32x4_t x) {
    return veorq_u32(veorq_u32(x, ROL32_NEON(x, 9)), ROL32_NEON(x, 17));
}

#define SM3_BLOCK_SIZE 64
typedef struct {
    uint32_t digest[8];
    uint8_t block[SM3_BLOCK_SIZE];
    size_t num;
    size_t nblocks;
} SM3_CTX;

// ============================================================
// 版本1：基础实现（纯 C 标量，无 SIMD）
// ============================================================
void sm3_compress_blocks_baseline(uint32_t digest[8], const uint8_t *data, size_t blocks) {
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t W[68];
    uint32_t SS0, SS1, SS2;
    int j;

    while (blocks--) {
        A = digest[0]; B = digest[1]; C = digest[2]; D = digest[3];
        E = digest[4]; F = digest[5]; G = digest[6]; H = digest[7];

        for (j = 0; j < 16; j++) W[j] = GETU32(data + j*4);
        for (; j < 68; j++) {
            W[j] = P1(W[j-16] ^ W[j-9] ^ ROL32(W[j-3], 15)) ^ ROL32(W[j-13], 7) ^ W[j-6];
        }

        for (j = 0; j < 16; j++) {
            SS1 = ROL32((ROL32(A, 12) + E + K[j]), 7);
            SS2 = SS1 ^ ROL32(A, 12);
            uint32_t TT1 = FF00(A, B, C) + D + SS2 + (W[j] ^ W[j+4]);
            uint32_t TT2 = GG00(E, F, G) + H + SS1 + W[j];
            D = C; C = ROL32(B, 9); B = A; A = TT1;
            H = G; G = ROL32(F, 19); F = E; E = P0(TT2);
        }
        for (; j < 64; j++) {
            SS1 = ROL32((ROL32(A, 12) + E + K[j]), 7);
            SS2 = SS1 ^ ROL32(A, 12);
            uint32_t TT1 = FF16(A, B, C) + D + SS2 + (W[j] ^ W[j+4]);
            uint32_t TT2 = GG16(E, F, G) + H + SS1 + W[j];
            D = C; C = ROL32(B, 9); B = A; A = TT1;
            H = G; G = ROL32(F, 19); F = E; E = P0(TT2);
        }
        digest[0] ^= A; digest[1] ^= B; digest[2] ^= C; digest[3] ^= D;
        digest[4] ^= E; digest[5] ^= F; digest[6] ^= G; digest[7] ^= H;
        data += 64;
    }
}

// ============================================================
// 版本2：NEON 优化实现（消息扩展 4 路 SIMD 并行）
// ============================================================
void sm3_compress_blocks_neon(uint32_t digest[8], const uint8_t *data, size_t blocks) {
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t W[68];
    uint32_t SS0, SS1, SS2;
    int j;

    while (blocks--) {
        A = digest[0]; B = digest[1]; C = digest[2]; D = digest[3];
        E = digest[4]; F = digest[5]; G = digest[6]; H = digest[7];

        for (j = 0; j < 16; j++) W[j] = GETU32(data + j*4);

        // NEON 加速消息扩展：每轮计算 4 个 W
        for (j = 16; j < 68; j += 4) {
            uint32x4_t w0 = vld1q_u32(&W[j-16]);
            uint32x4_t w1 = vld1q_u32(&W[j-9]);
            uint32x4_t w2 = vld1q_u32(&W[j-3]);
            uint32x4_t w3 = vld1q_u32(&W[j-13]);
            uint32x4_t w4 = vld1q_u32(&W[j-6]);
            uint32x4_t wj = P1_NEON(veorq_u32(veorq_u32(w0, w1), ROL32_NEON(w2, 15)));
            wj = veorq_u32(wj, veorq_u32(ROL32_NEON(w3, 7), w4));
            vst1q_u32(&W[j], wj);
        }

        for (j = 0; j < 16; j++) {
            SS1 = ROL32((ROL32(A, 12) + E + K[j]), 7);
            SS2 = SS1 ^ ROL32(A, 12);
            uint32_t TT1 = FF00(A, B, C) + D + SS2 + (W[j] ^ W[j+4]);
            uint32_t TT2 = GG00(E, F, G) + H + SS1 + W[j];
            D = C; C = ROL32(B, 9); B = A; A = TT1;
            H = G; G = ROL32(F, 19); F = E; E = P0(TT2);
        }
        for (; j < 64; j++) {
            SS1 = ROL32((ROL32(A, 12) + E + K[j]), 7);
            SS2 = SS1 ^ ROL32(A, 12);
            uint32_t TT1 = FF16(A, B, C) + D + SS2 + (W[j] ^ W[j+4]);
            uint32_t TT2 = GG16(E, F, G) + H + SS1 + W[j];
            D = C; C = ROL32(B, 9); B = A; A = TT1;
            H = G; G = ROL32(F, 19); F = E; E = P0(TT2);
        }
        digest[0] ^= A; digest[1] ^= B; digest[2] ^= C; digest[3] ^= D;
        digest[4] ^= E; digest[5] ^= F; digest[6] ^= G; digest[7] ^= H;
        data += 64;
    }
}

// ============================================================
// 核心函数：根据编译宏选择使用哪个版本
// 编译时加 -DUSE_NEON=1 使用 NEON 优化版本
// 不加则使用基础版本
// ============================================================
void sm3_compress_blocks(uint32_t digest[8], const uint8_t *data, size_t blocks) {
#ifdef USE_NEON
    sm3_compress_blocks_neon(digest, data, blocks);
#else
    sm3_compress_blocks_baseline(digest, data, blocks);
#endif
}

void sm3_init(SM3_CTX *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->digest[0] = 0x7380166F; ctx->digest[1] = 0x4914B2B9;
    ctx->digest[2] = 0x172442D7; ctx->digest[3] = 0xDA8A0600;
    ctx->digest[4] = 0xA96F30BC; ctx->digest[5] = 0x163138AA;
    ctx->digest[6] = 0xE38DEE4D; ctx->digest[7] = 0xB0FB0E4E;
}

void sm3_update(SM3_CTX *ctx, const uint8_t *data, size_t data_len) {
    size_t blocks;
    if (!data || !data_len) return;
    ctx->num &= 0x3f;
    if (ctx->num) {
        size_t left = SM3_BLOCK_SIZE - ctx->num;
        if (data_len < left) {
            memcpy(ctx->block + ctx->num, data, data_len);
            ctx->num += data_len;
            return;
        } else {
            memcpy(ctx->block + ctx->num, data, left);
            sm3_compress_blocks(ctx->digest, ctx->block, 1);
            ctx->nblocks++;
            data += left; data_len -= left;
        }
    }
    blocks = data_len / SM3_BLOCK_SIZE;
    if (blocks) {
        sm3_compress_blocks(ctx->digest, data, blocks);
        ctx->nblocks += blocks;
        data += SM3_BLOCK_SIZE * blocks;
        data_len -= SM3_BLOCK_SIZE * blocks;
    }
    ctx->num = data_len;
    if (data_len) memcpy(ctx->block, data, data_len);
}

void sm3_finish(SM3_CTX *ctx, uint8_t *digest) {
    int i;
    ctx->num &= 0x3f;
    ctx->block[ctx->num] = 0x80;
    if (ctx->num <= SM3_BLOCK_SIZE - 9) {
        memset(ctx->block + ctx->num + 1, 0, SM3_BLOCK_SIZE - ctx->num - 9);
    } else {
        memset(ctx->block + ctx->num + 1, 0, SM3_BLOCK_SIZE - ctx->num - 1);
        sm3_compress_blocks(ctx->digest, ctx->block, 1);
        memset(ctx->block, 0, SM3_BLOCK_SIZE - 8);
    }
    for (i = 0; i < 8; i++) {
        ctx->block[56 + i] = (uint8_t)(ctx->nblocks >> (23 - i*8));
    }
    ctx->block[60] = (uint8_t)((ctx->nblocks << 9) >> 24);
    ctx->block[61] = (uint8_t)((ctx->nblocks << 9) >> 16);
    ctx->block[62] = (uint8_t)((ctx->nblocks << 9) >> 8);
    ctx->block[63] = (uint8_t)((ctx->nblocks << 9) + (ctx->num << 3));
    sm3_compress_blocks(ctx->digest, ctx->block, 1);
    for (i = 0; i < 8; i++) {
        digest[i*4] = (uint8_t)(ctx->digest[i] >> 24);
        digest[i*4+1] = (uint8_t)(ctx->digest[i] >> 16);
        digest[i*4+2] = (uint8_t)(ctx->digest[i] >> 8);
        digest[i*4+3] = (uint8_t)(ctx->digest[i]);
    }
}