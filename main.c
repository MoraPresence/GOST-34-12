#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <stdint.h>
//static const int lut[32] = {0, 9, 1, 10, 13, 21, 2, 29, 11, 14, 16, 18, 22, 25, 3, 30,
//                            8, 12, 20, 28, 15, 17, 24, 7, 19, 27, 23, 6, 26, 5, 4, 31};
//
//static unsigned int number_of_bits(unsigned int v) {
//    v |= v >> 1;
//    v |= v >> 2;
//    v |= v >> 4;
//    v |= v >> 8;
//    v |= v >> 16;
//
//    return lut[(unsigned int) (v * 0x07C4ACDDU) >> 27] + 1;
//} интересный способ

unsigned char tableMult[256][256];

unsigned pi[256] = {252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233,
                    119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249, 24, 101,
                    90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143,
                    160, 6, 11, 237, 152, 127, 212, 211, 31, 235, 52, 44, 81, 234, 200, 72, 171, 242, 42,
                    104, 162, 253, 58, 206, 204, 181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156,
                    183, 93, 135, 21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178,
                    177, 50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87, 223,
                    245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3, 224, 15, 236,
                    222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 167, 151, 96, 115, 30, 0,
                    98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70, 146, 39, 94, 85, 47, 140, 163,
                    165, 125, 105, 213, 149, 59, 7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136,
                    217, 231, 137, 225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133,
                    97, 32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166,
                    116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182};

unsigned tableForL[16] = {148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1};

union uint128 {
    uint64_t qw[2];
    uint8_t b[16];
    uint32_t dw[4];
    uint16_t w[8];
} typedef uint128;

//----------------------------------------------------------------------------------------------------------------
uint128 X(uint128 a, uint128 b);

uint128 S(uint128 a);

uint128 R(uint128 a);

uint128 L(uint128 a);

uint8_t getRemainder(uint16_t  dividend, uint16_t divisor);

unsigned summ(unsigned a, unsigned b);

uint8_t mult(uint16_t a, uint16_t b, uint16_t p);

void **fillMultTable();

uint8_t fastMult(uint8_t a, uint8_t b);
//----------------------------------------------------------------------------------------------------------------

uint128 X(uint128 a, uint128 b) {
    uint128 c;
    c.qw[0] = a.qw[0] ^ b.qw[0];
    c.qw[1] = a.qw[1] ^ b.qw[1];
    return c;
}

uint128 S(uint128 a) {
    uint128 c;
    int i;
    for (i = 0; i < 16; ++i) {
        c.b[i] = pi[a.b[i]];
    }
    return c;
}

uint128 R(uint128 a) {
    uint128 c;
    unsigned sum = 0;
    int i;
    for (i = 0; i < 16; ++i) {
        sum ^= fastMult(a.b[15 - i], tableForL[i]);
    }
    c.b[15] = sum;
    for (i = 1; i < 16; ++i) {
        c.b[15 - i] = a.b[16 - i];
    }
    return c;
}

uint128 L(uint128 a) {
    uint128 c;
    uint8_t tmp[32];
    uint128 tmpB;
    int i = 0;
    int j = 0;
    memset(tmp, 0, sizeof(uint8_t) * 32);
    memcpy(tmp, a.b, 16);
    for (i = 0; i < 16; ++i) {
        for (j = 0; j < 16; ++j) {
            tmpB.b[j] = tmp[j + i];
        }
        tmp[i + 16] = R(tmpB).b[15];
    }

    for (i = 0; i < 16; ++i) {
        c.b[i] = tmp[i + 16];
    }
    return c;
}

uint8_t getRemainder(uint16_t dividend, uint16_t divisor) {
    uint16_t mask = 0x8000;
    divisor <<= 7;
    while (dividend & 0xff00) {
       // printf("a=0x%x, d=0x%x, m=0x%x (%x)\n", dividend, divisor, mask, (dividend & 0xff00));
        if (dividend & mask)
            dividend ^= divisor;
        mask >>= 1;
        divisor >>= 1;
    }
    return dividend;
}

unsigned summ(unsigned a, unsigned b) {
    return a ^ b;
}

uint8_t mult(uint16_t a, uint16_t b, uint16_t p) {
    uint16_t x = 0;
    while (b != 0) {
        if ((b & 0x1) == 0x1)
            x ^= a;
        b >>= 1;
        a <<= 1;
    }
    return getRemainder(x, p);
}

void **fillMultTable() {
    uint16_t i = 0;
    uint16_t j = 0;
    memset(tableMult, 0, 256 * sizeof(unsigned *));
    for (i = 0; i < 256; ++i) {
        memset(tableMult[i], 0, 256 * sizeof(unsigned));
    }

    for (i = 0; i < 256; ++i) {
        for (j = 0; j < 256; ++j) {
            tableMult[i][j] = mult(i, j, 0b111000011);
        }
    }
    return NULL;
}

uint8_t fastMult(uint8_t a, uint8_t b) {
    return tableMult[a][b];
}

int main() {
    fillMultTable();
    printf("0x%x\n", mult(83, 9, 0b111000011));
    printf("0x%x\n", fastMult(0x94, 133));
    printf("0x%x\n", summ(83, 9));
    uint128 a;
    a.qw[0] = 0x1122334455667700;
    a.qw[1] = 0xffeeddccbbaa9988;
    uint128 c = S(a);
    int i;
    for (i = 0; i < 2; ++i) {
        printf("%016llx", c.qw[1 - i]); //b66cd8887d38e8d77765aeea0c9a7efc
    }
    printf("\n");
    uint128 d;

    d.qw[0] = 0x0000000000000000;
    d.qw[1] = 0x64a5940000000000;
    c = R(d);
    for (i = 0; i < 16; ++i) {
        printf("%02x", c.b[15 - i]); //0d64a594000000000000000000000000
    }
    printf("\n");
    uint128 a1;

    a1.qw[0] = 0x8b7b68f66b513c13;
    a1.qw[1] = 0x0e93691a0cfc6040;
    c = L(a1);
    for (i = 0; i < 16; ++i) {
        printf("%02x", c.b[15 - i]); //e6a8094fee0aa204fd97bcb0b44b8580
    }
    return 0;
}