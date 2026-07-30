/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <string.h>
#include <gmssl/sm3.h>
#include <gmssl/error.h>
#include <gmssl/endian.h>
#include <immintrin.h>
#include <stdio.h>
#define P0(x) ((x) ^ ROL32((x), 9) ^ ROL32((x),17))
#define P1(x) ((x) ^ ROL32((x),15) ^ ROL32((x),23))

#define FF00(x,y,z)  ((x) ^ (y) ^ (z))
#define FF16(x,y,z)  (((x)&(y)) | ((x)&(z)) | ((y)&(z)))
#define GG00(x,y,z)  ((x) ^ (y) ^ (z))
#define GG16(x,y,z)  ((((y)^(z)) & (x)) ^ (z))

static inline __m256i ROL32_AVX2(__m256i x, int n)
{
    return _mm256_or_si256(
        _mm256_slli_epi32(x,n),
        _mm256_srli_epi32(x,32-n)
    );
}

static inline __m256i FF0_AVX2(
        __m256i x,
        __m256i y,
        __m256i z)
{
    return _mm256_xor_si256(
        _mm256_xor_si256(x,y),
        z);
}



static inline __m256i FF1_AVX2(
        __m256i x,
        __m256i y,
        __m256i z)
{
    return _mm256_or_si256(
        _mm256_or_si256(
            _mm256_and_si256(x,y),
            _mm256_and_si256(x,z)),
        _mm256_and_si256(y,z));
}



static inline __m256i GG0_AVX2(
        __m256i x,
        __m256i y,
        __m256i z)
{
    return _mm256_xor_si256(
        _mm256_xor_si256(x,y),
        z);
}



static inline __m256i GG1_AVX2(
        __m256i x,
        __m256i y,
        __m256i z)
{
    return _mm256_xor_si256(
        _mm256_and_si256(
            _mm256_xor_si256(y,z),
            x),
        z);
}



static inline __m256i P0_AVX2(__m256i x)
{
    return _mm256_xor_si256(
        _mm256_xor_si256(
            x,
            ROL32_AVX2(x,9)),
            ROL32_AVX2(x,17));
}


static inline __m256i P1_AVX2(__m256i x)
{
    return _mm256_xor_si256(
        _mm256_xor_si256(
            x,
            ROL32_AVX2(x,15)),
            ROL32_AVX2(x,23));
}
static const  uint32_t K[64] = {
	0x79cc4519U, 0xf3988a32U, 0xe7311465U, 0xce6228cbU,
	0x9cc45197U, 0x3988a32fU, 0x7311465eU, 0xe6228cbcU,
	0xcc451979U, 0x988a32f3U, 0x311465e7U, 0x6228cbceU,
	0xc451979cU, 0x88a32f39U, 0x11465e73U, 0x228cbce6U,
	0x9d8a7a87U, 0x3b14f50fU, 0x7629ea1eU, 0xec53d43cU,
	0xd8a7a879U, 0xb14f50f3U, 0x629ea1e7U, 0xc53d43ceU,
	0x8a7a879dU, 0x14f50f3bU, 0x29ea1e76U, 0x53d43cecU,
	0xa7a879d8U, 0x4f50f3b1U, 0x9ea1e762U, 0x3d43cec5U,
	0x7a879d8aU, 0xf50f3b14U, 0xea1e7629U, 0xd43cec53U,
	0xa879d8a7U, 0x50f3b14fU, 0xa1e7629eU, 0x43cec53dU,
	0x879d8a7aU, 0x0f3b14f5U, 0x1e7629eaU, 0x3cec53d4U,
	0x79d8a7a8U, 0xf3b14f50U, 0xe7629ea1U, 0xcec53d43U,
	0x9d8a7a87U, 0x3b14f50fU, 0x7629ea1eU, 0xec53d43cU,
	0xd8a7a879U, 0xb14f50f3U, 0x629ea1e7U, 0xc53d43ceU,
	0x8a7a879dU, 0x14f50f3bU, 0x29ea1e76U, 0x53d43cecU,
	0xa7a879d8U, 0x4f50f3b1U, 0x9ea1e762U, 0x3d43cec5U,
};
static inline uint32_t sm3_w_expand_opt(
        uint32_t w0,
        uint32_t w1,
        uint32_t w2,
        uint32_t w3,
        uint32_t w4)
{

    uint32_t tmp;


    tmp = w0 ^ w1 ^ ROL32(w2,15);


    tmp = P1(tmp)
          ^ ROL32(w3,7)
          ^ w4;


    return tmp;
}
#if ENABLE_SMALL_FOOTPRINT
void sm3_compress_blocks(
        uint32_t digest[8],
        const uint8_t *data,
        size_t blocks)
{
        uint32_t A;
        uint32_t B;
        uint32_t C;
        uint32_t D;
        uint32_t E;
        uint32_t F;
        uint32_t G;
        uint32_t H;
	uint32_t W[68];
	uint32_t SS1, SS2, TT1, TT2;
	int j;

	while (blocks--) {

		A = digest[0];
		B = digest[1];
		C = digest[2];
		D = digest[3];
		E = digest[4];
		F = digest[5];
		G = digest[6];
		H = digest[7];

		for (j = 0; j < 16; j++) {
			W[j] = GETU32(data + j*4);
		}

		for (; j < 68; j++) {
			W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROL32(W[j - 3], 15))
				^ ROL32(W[j - 13], 7) ^ W[j - 6];
		}

		for (j = 0; j < 16; j++) {
			SS1 = ROL32((ROL32(A, 12) + E + K[j]), 7);
			SS2 = SS1 ^ ROL32(A, 12);
			TT1 = FF00(A, B, C) + D + SS2 + (W[j] ^ W[j + 4]);
			TT2 = GG00(E, F, G) + H + SS1 + W[j];
			D = C;
			C = ROL32(B, 9);
			B = A;
			A = TT1;
			H = G;
			G = ROL32(F, 19);
			F = E;
			E = P0(TT2);
		}

		for (; j < 64; j++) {
			SS1 = ROL32((ROL32(A, 12) + E + K[j]), 7);
			SS2 = SS1 ^ ROL32(A, 12);
			TT1 = FF16(A, B, C) + D + SS2 + (W[j] ^ W[j + 4]);
			TT2 = GG16(E, F, G) + H + SS1 + W[j];
			D = C;
			C = ROL32(B, 9);
			B = A;
			A = TT1;
			H = G;
			G = ROL32(F, 19);
			F = E;
			E = P0(TT2);
		}

		digest[0] ^= A;
		digest[1] ^= B;
		digest[2] ^= C;
		digest[3] ^= D;
		digest[4] ^= E;
		digest[5] ^= F;
		digest[6] ^= G;
		digest[7] ^= H;

		data += 64;
	}
}
#else

#define SM3_ROUND_0(j,A,B,C,D,E,F,G,H)			\
	SS0 = ROL32(A, 12);				\
	SS1 = ROL32(SS0 + E + K[j], 7);			\
	SS2 = SS1 ^ SS0;				\
	D += FF00(A, B, C) + SS2 + (W[j] ^ W[j + 4]);	\
	SS1 += GG00(E, F, G) + H + W[j];		\
	B = ROL32(B, 9);				\
	H = P0(SS1);					\
	F = ROL32(F, 19);				\
	W[j+16] =sm3_w_expand_opt(W[j],W[j+7],W[j+13],W[j+3],W[j+10]);

#define SM3_ROUND_1(j,A,B,C,D,E,F,G,H)			\
	SS0 = ROL32(A, 12);				\
	SS1 = ROL32(SS0 + E + K[j], 7);			\
	SS2 = SS1 ^ SS0;				\
	D += FF16(A, B, C) + SS2 + (W[j] ^ W[j + 4]);	\
	SS1 += GG16(E, F, G) + H + W[j];		\
	B = ROL32(B, 9);					\
	H = P0(SS1);					\
	F = ROL32(F, 19);				\
	W[j+16] =sm3_w_expand_opt(W[j],W[j+7],W[j+13],W[j+3],W[j+10]);


#define SM3_ROUND_2(j,A,B,C,D,E,F,G,H)			\
	SS0 = ROL32(A, 12);				\
	SS1 = ROL32(SS0 + E + K[j], 7);			\
	SS2 = SS1 ^ SS0;				\
	D += FF16(A, B, C) + SS2 + (W[j] ^ W[j + 4]);	\
	SS1 += GG16(E, F, G) + H + W[j];		\
	B = ROL32(B, 9);				\
	H = P0(SS1);					\
	F = ROL32(F, 19);

void sm3_compress_blocks(uint32_t digest[8], const uint8_t *data, size_t blocks)
{
#ifdef __AVX2__

        __m256i A_vec;
        __m256i B_vec;
        __m256i C_vec;
        __m256i D_vec;
        __m256i E_vec;
        __m256i F_vec;
        __m256i G_vec;
        __m256i H_vec;

#endif
	uint32_t A;
        uint32_t B;
        uint32_t C;
        uint32_t D;
        uint32_t E;
        uint32_t F;
        uint32_t G;
        uint32_t H;
	uint32_t W[68];
	uint32_t SS0, SS1, SS2;
	int j;

	while (blocks--) {

		A = digest[0];
		B = digest[1];
		C = digest[2];
		D = digest[3];
		E = digest[4];
		F = digest[5];
		G = digest[6];
		H = digest[7];

		for (j = 0; j < 16; j++) {
			W[j] = GETU32(data + j*4);
		}

		SM3_ROUND_0( 0, A,B,C,D, E,F,G,H);
		SM3_ROUND_0( 1, D,A,B,C, H,E,F,G);
		SM3_ROUND_0( 2, C,D,A,B, G,H,E,F);
		SM3_ROUND_0( 3, B,C,D,A, F,G,H,E);
		SM3_ROUND_0( 4, A,B,C,D, E,F,G,H);
		SM3_ROUND_0( 5, D,A,B,C, H,E,F,G);
		SM3_ROUND_0( 6, C,D,A,B, G,H,E,F);
		SM3_ROUND_0( 7, B,C,D,A, F,G,H,E);
		SM3_ROUND_0( 8, A,B,C,D, E,F,G,H);
		SM3_ROUND_0( 9, D,A,B,C, H,E,F,G);
		SM3_ROUND_0(10, C,D,A,B, G,H,E,F);
		SM3_ROUND_0(11, B,C,D,A, F,G,H,E);
		SM3_ROUND_0(12, A,B,C,D, E,F,G,H);
		SM3_ROUND_0(13, D,A,B,C, H,E,F,G);
		SM3_ROUND_0(14, C,D,A,B, G,H,E,F);
		SM3_ROUND_0(15, B,C,D,A, F,G,H,E);
		SM3_ROUND_1(16, A,B,C,D, E,F,G,H);
		SM3_ROUND_1(17, D,A,B,C, H,E,F,G);
		SM3_ROUND_1(18, C,D,A,B, G,H,E,F);
		SM3_ROUND_1(19, B,C,D,A, F,G,H,E);
		SM3_ROUND_1(20, A,B,C,D, E,F,G,H);
		SM3_ROUND_1(21, D,A,B,C, H,E,F,G);
		SM3_ROUND_1(22, C,D,A,B, G,H,E,F);
		SM3_ROUND_1(23, B,C,D,A, F,G,H,E);
		SM3_ROUND_1(24, A,B,C,D, E,F,G,H);
		SM3_ROUND_1(25, D,A,B,C, H,E,F,G);
		SM3_ROUND_1(26, C,D,A,B, G,H,E,F);
		SM3_ROUND_1(27, B,C,D,A, F,G,H,E);
		SM3_ROUND_1(28, A,B,C,D, E,F,G,H);
		SM3_ROUND_1(29, D,A,B,C, H,E,F,G);
		SM3_ROUND_1(30, C,D,A,B, G,H,E,F);
		SM3_ROUND_1(31, B,C,D,A, F,G,H,E);
		SM3_ROUND_1(32, A,B,C,D, E,F,G,H);
		SM3_ROUND_1(33, D,A,B,C, H,E,F,G);
		SM3_ROUND_1(34, C,D,A,B, G,H,E,F);
		SM3_ROUND_1(35, B,C,D,A, F,G,H,E);
		SM3_ROUND_1(36, A,B,C,D, E,F,G,H);
		SM3_ROUND_1(37, D,A,B,C, H,E,F,G);
		SM3_ROUND_1(38, C,D,A,B, G,H,E,F);
		SM3_ROUND_1(39, B,C,D,A, F,G,H,E);
		SM3_ROUND_1(40, A,B,C,D, E,F,G,H);
		SM3_ROUND_1(41, D,A,B,C, H,E,F,G);
		SM3_ROUND_1(42, C,D,A,B, G,H,E,F);
		SM3_ROUND_1(43, B,C,D,A, F,G,H,E);
		SM3_ROUND_1(44, A,B,C,D, E,F,G,H);
		SM3_ROUND_1(45, D,A,B,C, H,E,F,G);
		SM3_ROUND_1(46, C,D,A,B, G,H,E,F);
		SM3_ROUND_1(47, B,C,D,A, F,G,H,E);
		SM3_ROUND_1(48, A,B,C,D, E,F,G,H);
		SM3_ROUND_1(49, D,A,B,C, H,E,F,G);
		SM3_ROUND_1(50, C,D,A,B, G,H,E,F);
		SM3_ROUND_1(51, B,C,D,A, F,G,H,E);
		SM3_ROUND_2(52, A,B,C,D, E,F,G,H);
		SM3_ROUND_2(53, D,A,B,C, H,E,F,G);
		SM3_ROUND_2(54, C,D,A,B, G,H,E,F);
		SM3_ROUND_2(55, B,C,D,A, F,G,H,E);
		SM3_ROUND_2(56, A,B,C,D, E,F,G,H);
		SM3_ROUND_2(57, D,A,B,C, H,E,F,G);
		SM3_ROUND_2(58, C,D,A,B, G,H,E,F);
		SM3_ROUND_2(59, B,C,D,A, F,G,H,E);
		SM3_ROUND_2(60, A,B,C,D, E,F,G,H);
		SM3_ROUND_2(61, D,A,B,C, H,E,F,G);
		SM3_ROUND_2(62, C,D,A,B, G,H,E,F);
		SM3_ROUND_2(63, B,C,D,A, F,G,H,E);

		digest[0] ^= A;
		digest[1] ^= B;
		digest[2] ^= C;
		digest[3] ^= D;
		digest[4] ^= E;
		digest[5] ^= F;
		digest[6] ^= G;
		digest[7] ^= H;

		data += 64;
	}
}
#endif

void sm3_init(SM3_CTX *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->digest[0] = 0x7380166F;
	ctx->digest[1] = 0x4914B2B9;
	ctx->digest[2] = 0x172442D7;
	ctx->digest[3] = 0xDA8A0600;
	ctx->digest[4] = 0xA96F30BC;
	ctx->digest[5] = 0x163138AA;
	ctx->digest[6] = 0xE38DEE4D;
	ctx->digest[7] = 0xB0FB0E4E;
}

void sm3_update(SM3_CTX *ctx, const uint8_t *data, size_t data_len)
{
	size_t blocks;

	if (!data || !data_len) {
		return;
	}

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
			data += left;
			data_len -= left;
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
	if (data_len) {
		memcpy(ctx->block, data, data_len);
	}
}

void sm3_finish(SM3_CTX *ctx, uint8_t *digest)
{
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

	PUTU32(ctx->block + 56, ctx->nblocks >> 23);
	PUTU32(ctx->block + 60, (ctx->nblocks << 9) + (ctx->num << 3));
	sm3_compress_blocks(ctx->digest, ctx->block, 1);

	for (i = 0; i < 8; i++) {
		PUTU32(digest + i*4, ctx->digest[i]);
	}
}


static inline __m256i load_state8(
        uint32_t digest[8][8],
        int index)
{
    return _mm256_set_epi32(
        digest[7][index],
        digest[6][index],
        digest[5][index],
        digest[4][index],
        digest[3][index],
        digest[2][index],
        digest[1][index],
        digest[0][index]
    );
}
static inline void store_state8(
        uint32_t digest[8][8],
        int index,
        __m256i x)
{
    uint32_t tmp[8];

    _mm256_storeu_si256(
        (__m256i*)tmp,
        x);

    digest[0][index]=tmp[0];
    digest[1][index]=tmp[1];
    digest[2][index]=tmp[2];
    digest[3][index]=tmp[3];
    digest[4][index]=tmp[4];
    digest[5][index]=tmp[5];
    digest[6][index]=tmp[6];
    digest[7][index]=tmp[7];
}
static inline __m256i load_word8(
        const uint8_t *data[8],
        int offset)
{

    return _mm256_set_epi32(

        GETU32(data[7]+offset),
        GETU32(data[6]+offset),
        GETU32(data[5]+offset),
        GETU32(data[4]+offset),
        GETU32(data[3]+offset),
        GETU32(data[2]+offset),
        GETU32(data[1]+offset),
        GETU32(data[0]+offset)

    );
}
static inline __m256i sm3_w_expand_avx2(
        __m256i w0,
        __m256i w1,
        __m256i w2,
        __m256i w3,
        __m256i w4)
{
    __m256i tmp;


    tmp = _mm256_xor_si256(
            _mm256_xor_si256(
                w0,
                w1),
            ROL32_AVX2(w2,15));


    return _mm256_xor_si256(
            _mm256_xor_si256(
                P1_AVX2(tmp),
                ROL32_AVX2(w3,7)),
            w4);
}
void sm3_compress_blocks_8way(
        uint32_t digest[8][8],
        const uint8_t *data[8])
{

    __m256i A,B,C,D;
    __m256i E,F,G,H;


    __m256i W[68];


    int j;


    /*
     * load initial state
     */

    A = load_state8(digest,0);
    B = load_state8(digest,1);
    C = load_state8(digest,2);
    D = load_state8(digest,3);

    E = load_state8(digest,4);
    F = load_state8(digest,5);
    G = load_state8(digest,6);
    H = load_state8(digest,7);



    /*
     * load message words
     */

    for(j=0;j<16;j++)
    {
        W[j]=load_word8(data,j*4);
    }



    /*
     * message expansion
     */

    for(j=16;j<68;j++)
    {

        W[j]=sm3_w_expand_avx2(
                W[j-16],
                W[j-9],
                W[j-3],
                W[j-13],
                W[j-6]);

    }
        /*
     * SM3 compression 64 rounds
     */

    for(j=0;j<64;j++)
    {

        __m256i SS0;
        __m256i SS1;
        __m256i SS2;

        __m256i TT1;
        __m256i TT2;


        SS0 = ROL32_AVX2(A,12);


        SS1 = ROL32_AVX2(
                _mm256_add_epi32(
                    _mm256_add_epi32(
                        SS0,
                        E),
                    _mm256_set1_epi32(K[j])),
                7);


        SS2 = _mm256_xor_si256(
                SS1,
                SS0);


        if(j < 16)
        {

            TT1 = _mm256_add_epi32(
                    _mm256_add_epi32(
                        FF0_AVX2(A,B,C),
                        D),
                    SS2);


            TT1 = _mm256_add_epi32(
                    TT1,
                    _mm256_xor_si256(
                        W[j],
                        W[j+4]));



            TT2 = _mm256_add_epi32(
                    _mm256_add_epi32(
                        GG0_AVX2(E,F,G),
                        H),
                    SS1);


            TT2 = _mm256_add_epi32(
                    TT2,
                    W[j]);

        }
        else
        {

            TT1 = _mm256_add_epi32(
                    _mm256_add_epi32(
                        FF1_AVX2(A,B,C),
                        D),
                    SS2);


            TT1 = _mm256_add_epi32(
                    TT1,
                    _mm256_xor_si256(
                        W[j],
                        W[j+4]));



            TT2 = _mm256_add_epi32(
                    _mm256_add_epi32(
                        GG1_AVX2(E,F,G),
                        H),
                    SS1);


            TT2 = _mm256_add_epi32(
                    TT2,
                    W[j]);

        }


        D=C;

        C=ROL32_AVX2(B,9);

        B=A;

        A=TT1;


        H=G;

        G=ROL32_AVX2(F,19);

        F=E;

        E=P0_AVX2(TT2);

    }
        /*
     * feed forward
     */


    A=_mm256_xor_si256(
            A,
            load_state8(digest,0));

    B=_mm256_xor_si256(
            B,
            load_state8(digest,1));


    C=_mm256_xor_si256(
            C,
            load_state8(digest,2));


    D=_mm256_xor_si256(
            D,
            load_state8(digest,3));


    E=_mm256_xor_si256(
            E,
            load_state8(digest,4));


    F=_mm256_xor_si256(
            F,
            load_state8(digest,5));


    G=_mm256_xor_si256(
            G,
            load_state8(digest,6));


    H=_mm256_xor_si256(
            H,
            load_state8(digest,7));



    store_state8(digest,0,A);
    store_state8(digest,1,B);
    store_state8(digest,2,C);
    store_state8(digest,3,D);

    store_state8(digest,4,E);
    store_state8(digest,5,F);
    store_state8(digest,6,G);
    store_state8(digest,7,H);

}
