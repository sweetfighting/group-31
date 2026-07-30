#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <gmssl/sm3.h>


extern void sm3_compress_blocks_8way(
        uint32_t digest[8][8],
        const uint8_t *data[8]);


#define SIZE (1024*1024)


int main()
{

    uint8_t *buf[8];

    const uint8_t *ptr[8];


    uint32_t digest[8][8];


    for(int i=0;i<8;i++)
    {

        buf[i]=malloc(SIZE);

        for(int j=0;j<SIZE;j++)
            buf[i][j]=j&0xff;


        ptr[i]=buf[i];


        for(int k=0;k<8;k++)
            digest[i][k]=0;

    }


    clock_t start,end;


    start=clock();


    for(int r=0;r<100;r++)
{
    for(int b=0;b<SIZE/64;b++)
    {
        sm3_compress_blocks_8way(
            digest,
            ptr);

        for(int i=0;i<8;i++)
            ptr[i]+=64;
    }


    for(int i=0;i<8;i++)
        ptr[i]=buf[i];
}


    end=clock();



    double sec=
        (double)(end-start)/CLOCKS_PER_SEC;


    double mb=
(double)SIZE*8*100/1024/1024;


    printf("Processed %.2f MB\n",mb);

    printf("Time %.4f s\n",sec);


    printf("Speed %.2f MB/s\n",
        mb/sec);


volatile uint32_t checksum = 0;

for(int i=0;i<8;i++)
{
    checksum ^= digest[0][i];
}

    printf("checksum=%08x\n",checksum);
    printf("Digest:\n");

    for(int i=0;i<8;i++)
    {

        printf("%08x ",
            digest[0][i]);

    }

    printf("\n");


    return 0;
}
