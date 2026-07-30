#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <gmssl/sm3.h>


#define TEST_SIZE (1024*1024*100)


int main()
{
    uint8_t *data;
    uint8_t digest[32];

    data = malloc(TEST_SIZE);

    for(int i=0;i<TEST_SIZE;i++)
        data[i]=i&0xff;


    SM3_CTX ctx;


    clock_t start,end;


    start=clock();


    for(int i=0;i<10;i++)
    {
        sm3_init(&ctx);

        sm3_update(&ctx,
                   data,
                   TEST_SIZE);

        sm3_finish(&ctx,digest);
    }


    end=clock();


    double sec=
        (double)(end-start)/CLOCKS_PER_SEC;


    double mb =
        (double)TEST_SIZE*10/1024/1024;


    printf("Processed %.2f MB\n",mb);

    printf("Time %.4f s\n",sec);

    printf("Speed %.2f MB/s\n",
        mb/sec);


    free(data);

    return 0;
}
