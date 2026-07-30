#define _POSIX_C_SOURCE 200809L
#include "aes128.h"
#include "aes_modes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now_sec(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec*1e-9;}
static volatile uint64_t sink=0;
static uint64_t checksum(const uint8_t *p,size_t n){uint64_t s=0;for(size_t i=0;i<n;i+=4096)s=s*131u+p[i];return s;}
static void print_speed(const char *label,size_t bytes,int iters,double sec){double mib=(double)bytes*iters/(1024.0*1024.0);printf("%-30s %10.2f MiB/s\n",label,mib/sec);}

int main(void){
    const size_t n=4u*1024u*1024u;
    const int iters=4;
    uint8_t *in=(uint8_t*)malloc(n+32),*out=(uint8_t*)malloc(n+32);
    if(!in||!out){fprintf(stderr,"allocation failed\n");return 1;}
    for(size_t i=0;i<n+32;++i)in[i]=(uint8_t)(i*17u+11u);
    uint8_t key[16],key2[16],ctr[16]={0},iv[12]={0},du[16]={0},tag[16];
    for(unsigned i=0;i<16;++i){key[i]=(uint8_t)i;key2[i]=(uint8_t)(0xa0u+i);} ctr[15]=1;
    aes128_ctx ctx,tctx;aes128_init(&ctx,key);aes128_init(&tctx,key2);
    aes_cpu_features f=aes_detect_cpu_features();
    printf("CPU: SSSE3=%d AES-NI=%d PCLMUL=%d AVX2=%d VAES=%d\n",f.ssse3,f.aesni,f.pclmul,f.avx2,f.vaes);
    printf("Buffer: %.1f MiB, iterations: %d\n\n",n/(1024.0*1024.0),iters);

    for(int b=0;b<=AES_BACKEND_VAES;++b){
        aes_backend backend=(aes_backend)b;if(!aes_backend_is_supported(backend,f))continue;
        double t0=now_sec();
        for(int r=0;r<iters;++r){
            if(backend==AES_BACKEND_VAES){for(size_t i=0;i<n;i+=32)aes128_encrypt2_vaes(&ctx,in+i,out+i);}
            else{for(size_t i=0;i<n;i+=16)aes128_encrypt_block(&ctx,backend,in+i,out+i);}
        }
        double t1=now_sec();char label[80];snprintf(label,sizeof(label),"AES blocks / %s",aes_backend_name(backend));print_speed(label,n,iters,t1-t0);sink^=checksum(out,n);
    }
    puts("");
    for(int b=0;b<=AES_BACKEND_VAES;++b){
        aes_backend backend=(aes_backend)b;if(!aes_backend_is_supported(backend,f))continue;
        double t0=now_sec();for(int r=0;r<iters;++r)aes128_ctr_crypt(&ctx,backend,ctr,in,out,n);double t1=now_sec();
        char label[80];snprintf(label,sizeof(label),"CTR / %s",aes_backend_name(backend));print_speed(label,n,iters,t1-t0);sink^=checksum(out,n);
    }
    puts("");
    for(int b=0;b<=AES_BACKEND_VAES;++b){
        aes_backend backend=(aes_backend)b;if(!aes_backend_is_supported(backend,f))continue;
        double t0=now_sec();for(int r=0;r<iters;++r)aes128_gcm_encrypt(&ctx,backend,iv,NULL,0,in,n,out,tag,f.pclmul);double t1=now_sec();
        char label[100];snprintf(label,sizeof(label),"GCM / %s / %s",aes_backend_name(backend),f.pclmul?"PCLMUL":"scalar");print_speed(label,n,iters,t1-t0);sink^=checksum(out,n)^tag[0];
    }
    puts("");
    for(int b=0;b<=AES_BACKEND_VAES;++b){
        aes_backend backend=(aes_backend)b;if(!aes_backend_is_supported(backend,f))continue;
        double t0=now_sec();for(int r=0;r<iters;++r)aes128_xts_encrypt(&ctx,&tctx,backend,du,in,out,n);double t1=now_sec();
        char label[80];snprintf(label,sizeof(label),"XTS / %s",aes_backend_name(backend));print_speed(label,n,iters,t1-t0);sink^=checksum(out,n);
    }
    printf("\nchecksum=%llu (prevents dead-code elimination)\n",(unsigned long long)sink);
    free(in);free(out);return 0;
}
