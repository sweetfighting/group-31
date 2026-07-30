#include <stdio.h>
#include <stdint.h>
#include <gmssl/sm3.h>

extern void sm3_compress_blocks_8way(
        uint32_t digest[8][8],
        const uint8_t *data[8]);
extern void sm3_compress_blocks(
        uint32_t digest[8],
        const uint8_t *data,
        size_t blocks);
void print_digest(uint32_t d[8])
{
    int i;

    for(i=0;i<8;i++)
    {
        printf("%08x ",d[i]);
    }

    printf("\n");
}

int main()
{

    uint8_t msg[8][64];

    const uint8_t *ptr[8];

    uint32_t digest[8][8];


    int i,j;


    for(i=0;i<8;i++)
    {
        for(j=0;j<64;j++)
        {
            msg[i][j]=j;
        }

        ptr[i]=msg[i];


        digest[i][0]=0x7380166F;
        digest[i][1]=0x4914B2B9;
        digest[i][2]=0x172442D7;
        digest[i][3]=0xDA8A0600;
        digest[i][4]=0xA96F30BC;
        digest[i][5]=0x163138AA;
        digest[i][6]=0xE38DEE4D;
        digest[i][7]=0xB0FB0E4E;
    }


    sm3_compress_blocks_8way(
            digest,
            ptr);

    printf("\nAVX2 result:\n");

for(i=0;i<8;i++)
{
    print_digest(digest[i]);
}



/*
 * 普通SM3测试
 */

uint32_t normal[8];


normal[0]=0x7380166F;
normal[1]=0x4914B2B9;
normal[2]=0x172442D7;
normal[3]=0xDA8A0600;
normal[4]=0xA96F30BC;
normal[5]=0x163138AA;
normal[6]=0xE38DEE4D;
normal[7]=0xB0FB0E4E;


sm3_compress_blocks(
        normal,
        msg[0],
        1);


printf("\nNormal compress:\n");


for(i=0;i<8;i++)
{
    printf("%08x ",normal[i]);
}

printf("\n");

    for(i=0;i<8;i++)
    {
        printf("digest %d:\n",i);

        for(j=0;j<8;j++)
        {
            printf("%08x ",
                    digest[i][j]);
        }

        printf("\n");
    }


    return 0;
}
