#include "aes128.h"
#include "aes_modes.h"
#include "ghash.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

static void check_bytes(const char *name, const uint8_t *got,
                        const uint8_t *expected, size_t n) {
    if (memcmp(got, expected, n) != 0) {
        printf("[FAIL] %s\n  got: ", name);
        for (size_t i=0;i<n;++i) printf("%02x", got[i]);
        printf("\n  exp: ");
        for (size_t i=0;i<n;++i) printf("%02x", expected[i]);
        printf("\n");
        ++failures;
    } else {
        printf("[PASS] %s\n", name);
    }
}

static void test_aes_blocks(aes_cpu_features f) {
    const uint8_t key[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                             0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    const uint8_t pt[16]  = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                             0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    const uint8_t ct[16]  = {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
                             0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
    aes128_ctx ctx;
    aes128_init(&ctx, key);
    for (int b=AES_BACKEND_REFERENCE; b<=AES_BACKEND_VAES; ++b) {
        aes_backend backend=(aes_backend)b;
        if (!aes_backend_is_supported(backend,f)) continue;
        uint8_t out[16], back[16];
        aes128_encrypt_block(&ctx,backend,pt,out);
        char name[80];
        snprintf(name,sizeof(name),"AES encrypt (%s)",aes_backend_name(backend));
        check_bytes(name,out,ct,16);
        aes128_decrypt_block(&ctx,backend,out,back);
        snprintf(name,sizeof(name),"AES decrypt (%s)",aes_backend_name(backend));
        check_bytes(name,back,pt,16);
    }
    if (aes_backend_is_supported(AES_BACKEND_VAES,f)) {
        uint8_t in2[32], out2[32], exp2[32];
        memcpy(in2,pt,16); memcpy(in2+16,pt,16);
        memcpy(exp2,ct,16); memcpy(exp2+16,ct,16);
        aes128_encrypt2_vaes(&ctx,in2,out2);
        check_bytes("VAES two-lane encryption",out2,exp2,32);
        aes128_decrypt2_vaes(&ctx,out2,in2);
        uint8_t exppt[32]; memcpy(exppt,pt,16); memcpy(exppt+16,pt,16);
        check_bytes("VAES two-lane decryption",in2,exppt,32);
    }
}

static void test_ctr(aes_cpu_features f) {
    const uint8_t key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                             0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    const uint8_t ctr[16] = {0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,
                             0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff};
    const uint8_t pt[64] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
        0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
        0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
        0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};
    const uint8_t ct[64] = {
        0x87,0x4d,0x61,0x91,0xb6,0x20,0xe3,0x26,0x1b,0xef,0x68,0x64,0x99,0x0d,0xb6,0xce,
        0x98,0x06,0xf6,0x6b,0x79,0x70,0xfd,0xff,0x86,0x17,0x18,0x7b,0xb9,0xff,0xfd,0xff,
        0x5a,0xe4,0xdf,0x3e,0xdb,0xd5,0xd3,0x5e,0x5b,0x4f,0x09,0x02,0x0d,0xb0,0x3e,0xab,
        0x1e,0x03,0x1d,0xda,0x2f,0xbe,0x03,0xd1,0x79,0x21,0x70,0xa0,0xf3,0x00,0x9c,0xee};
    aes128_ctx ctx; aes128_init(&ctx,key);
    for (int b=0;b<=AES_BACKEND_VAES;++b) {
        aes_backend backend=(aes_backend)b;
        if (!aes_backend_is_supported(backend,f)) continue;
        uint8_t out[64], back[64];
        aes128_ctr_crypt(&ctx,backend,ctr,pt,out,64);
        char name[80]; snprintf(name,sizeof(name),"CTR vector (%s)",aes_backend_name(backend));
        check_bytes(name,out,ct,64);
        aes128_ctr_crypt(&ctx,backend,ctr,out,back,64);
        snprintf(name,sizeof(name),"CTR decrypt (%s)",aes_backend_name(backend));
        check_bytes(name,back,pt,64);
    }
}

static void test_gcm(aes_cpu_features f) {
    const uint8_t key[16]={0};
    const uint8_t iv[12]={0};
    const uint8_t pt[16]={0};
    const uint8_t ct_exp[16]={0x03,0x88,0xda,0xce,0x60,0xb6,0xa3,0x92,
                              0xf3,0x28,0xc2,0xb9,0x71,0xb2,0xfe,0x78};
    const uint8_t tag_exp[16]={0xab,0x6e,0x47,0xd4,0x2c,0xec,0x13,0xbd,
                               0xf5,0x3a,0x67,0xb2,0x12,0x57,0xbd,0xdf};
    aes128_ctx ctx; aes128_init(&ctx,key);
    for (int b=0;b<=AES_BACKEND_VAES;++b) {
        aes_backend backend=(aes_backend)b;
        if (!aes_backend_is_supported(backend,f)) continue;
        for (int pcl=0;pcl<=1;++pcl) {
            if (pcl && !f.pclmul) continue;
            uint8_t ct[16],tag[16],back[16];
            aes128_gcm_encrypt(&ctx,backend,iv,NULL,0,pt,16,ct,tag,pcl);
            char name[100];
            snprintf(name,sizeof(name),"GCM ciphertext (%s,%s)",aes_backend_name(backend),pcl?"pclmul":"scalar");
            check_bytes(name,ct,ct_exp,16);
            snprintf(name,sizeof(name),"GCM tag (%s,%s)",aes_backend_name(backend),pcl?"pclmul":"scalar");
            check_bytes(name,tag,tag_exp,16);
            int ok=aes128_gcm_decrypt(&ctx,backend,iv,NULL,0,ct,16,tag,back,pcl);
            if (!ok) { printf("[FAIL] GCM verify\n"); ++failures; }
            else check_bytes("GCM decrypt",back,pt,16);
        }
    }
}

static void test_xts(aes_cpu_features f) {
    uint8_t k1[16],k2[16],du[16]={0},plain[97],refct[97];
    for (unsigned i=0;i<16;++i){k1[i]=(uint8_t)i;k2[i]=(uint8_t)(0xf0u+i);}
    for (unsigned i=0;i<97;++i)plain[i]=(uint8_t)(i*3u+1u);
    aes128_ctx dctx,tctx; aes128_init(&dctx,k1); aes128_init(&tctx,k2);
    const size_t lens[]={16,17,31,32,47,64,97};
    for (size_t li=0;li<sizeof(lens)/sizeof(lens[0]);++li) {
        size_t n=lens[li];
        aes128_xts_encrypt(&dctx,&tctx,AES_BACKEND_REFERENCE,du,plain,refct,n);
        for (int b=0;b<=AES_BACKEND_VAES;++b) {
            aes_backend backend=(aes_backend)b;
            if (!aes_backend_is_supported(backend,f)) continue;
            uint8_t ct[97],back[97];
            int ok1=aes128_xts_encrypt(&dctx,&tctx,backend,du,plain,ct,n);
            int ok2=aes128_xts_decrypt(&dctx,&tctx,backend,du,ct,back,n);
            char name[100];
            snprintf(name,sizeof(name),"XTS ciphertext n=%zu (%s)",n,aes_backend_name(backend));
            if (!ok1 || !ok2) { printf("[FAIL] %s API error\n",name); ++failures; continue; }
            check_bytes(name,ct,refct,n);
            snprintf(name,sizeof(name),"XTS roundtrip n=%zu (%s)",n,aes_backend_name(backend));
            check_bytes(name,back,plain,n);
        }
    }
}

int main(void) {
    aes_cpu_features f=aes_detect_cpu_features();
    printf("CPU: SSSE3=%d AES-NI=%d PCLMUL=%d AVX2=%d VAES=%d\n",
           f.ssse3,f.aesni,f.pclmul,f.avx2,f.vaes);
    test_aes_blocks(f);
    test_ctr(f);
    test_gcm(f);
    test_xts(f);
    if (failures) {
        printf("\n%d test(s) failed.\n",failures);
        return 1;
    }
    printf("\nAll tests passed.\n");
    return 0;
}
