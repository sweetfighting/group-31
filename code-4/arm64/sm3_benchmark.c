#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

// 直接包含 sm3 实现（这样就不用单独编译了）
#include "sm3_arm64_standalone.c"

#define TEST_SIZE (1024*1024*10)  // 10MB

int main() {
    uint8_t *data = malloc(TEST_SIZE);
    uint8_t digest[32];
    if (!data) {
        printf("malloc failed!\n");
        return 1;
    }
    for (int i = 0; i < TEST_SIZE; i++) data[i] = i & 0xff;

    SM3_CTX ctx;
    clock_t start = clock();

    for (int i = 0; i < 5; i++) {
        sm3_init(&ctx);
        sm3_update(&ctx, data, TEST_SIZE);
        sm3_finish(&ctx, digest);
    }

    clock_t end = clock();
    double sec = (double)(end - start) / CLOCKS_PER_SEC;
    double mb = (double)TEST_SIZE * 5 / 1024 / 1024;
    printf("Processed %.2f MB\n", mb);
    printf("Time %.4f s\n", sec);
    printf("Speed %.2f MB/s\n", mb / sec);

    free(data);
    return 0;
}
