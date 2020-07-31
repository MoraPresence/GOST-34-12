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

unsigned reversePi[256] = { 0xa5, 0x2d, 0x32, 0x8f, 0x0e, 0x30, 0x38, 0xc0, 0x54, 0xe6, 0x9e, 0x39,
                             0x55, 0x7e, 0x52, 0x91, 0x64, 0x03, 0x57, 0x5a, 0x1c, 0x60, 0x07, 0x18,
                             0x21, 0x72, 0xa8, 0xd1, 0x29, 0xc6, 0xa4, 0x3f, 0xe0, 0x27, 0x8d, 0x0c,
                             0x82, 0xea, 0xae, 0xb4, 0x9a, 0x63, 0x49, 0xe5, 0x42, 0xe4, 0x15, 0xb7,
                             0xc8, 0x06, 0x70, 0x9d, 0x41, 0x75, 0x19, 0xc9, 0xaa, 0xfc, 0x4d, 0xbf,
                             0x2a, 0x73, 0x84, 0xd5, 0xc3, 0xaf, 0x2b, 0x86, 0xa7, 0xb1, 0xb2, 0x5b,
                             0x46, 0xd3, 0x9f, 0xfd, 0xd4, 0x0f, 0x9c, 0x2f, 0x9b, 0x43, 0xef, 0xd9,
                             0x79, 0xb6, 0x53, 0x7f, 0xc1, 0xf0, 0x23, 0xe7, 0x25, 0x5e, 0xb5, 0x1e,
                             0xa2, 0xdf, 0xa6, 0xfe, 0xac, 0x22, 0xf9, 0xe2, 0x4a, 0xbc, 0x35, 0xca,
                             0xee, 0x78, 0x05, 0x6b, 0x51, 0xe1, 0x59, 0xa3, 0xf2, 0x71, 0x56, 0x11,
                             0x6a, 0x89, 0x94, 0x65, 0x8c, 0xbb, 0x77, 0x3c, 0x7b, 0x28, 0xab, 0xd2,
                             0x31, 0xde, 0xc4, 0x5f, 0xcc, 0xcf, 0x76, 0x2c, 0xb8, 0xd8, 0x2e, 0x36,
                             0xdb, 0x69, 0xb3, 0x14, 0x95, 0xbe, 0x62, 0xa1, 0x3b, 0x16, 0x66, 0xe9,
                             0x5c, 0x6c, 0x6d, 0xad, 0x37, 0x61, 0x4b, 0xb9, 0xe3, 0xba, 0xf1, 0xa0,
                             0x85, 0x83, 0xda, 0x47, 0xc5, 0xb0, 0x33, 0xfa, 0x96, 0x6f, 0x6e, 0xc2,
                             0xf6, 0x50, 0xff, 0x5d, 0xa9, 0x8e, 0x17, 0x1b, 0x97, 0x7d, 0xec, 0x58,
                             0xf7, 0x1f, 0xfb, 0x7c, 0x09, 0x0d, 0x7a, 0x67, 0x45, 0x87, 0xdc, 0xe8,
                             0x4f, 0x1d, 0x4e, 0x04, 0xeb, 0xf8, 0xf3, 0x3e, 0x3d, 0xbd, 0x8a, 0x88,
                             0xdd, 0xcd, 0x0b, 0x13, 0x98, 0x02, 0x93, 0x80, 0x90, 0xd0, 0x24, 0x34,
                             0xcb, 0xed, 0xf4, 0xce, 0x99, 0x10, 0x44, 0x40, 0x92, 0x3a, 0x01, 0x26,
                             0x12, 0x1a, 0x48, 0x68, 0xf5, 0x81, 0x8b, 0xc7, 0xd6, 0x20, 0x0a, 0x08,
                             0x00, 0x4c, 0xd7, 0x74};

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

uint128 reverseS(uint128 a);

uint128 reverseR(uint128 a);

uint128 reverseL(uint128 a);

uint128* F(uint128 c, uint128* k);

uint128* itConsts();

uint8_t getRemainder(uint16_t dividend, uint16_t divisor);

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

uint128 reverseS(uint128 a) {
    uint128 c;
    int i;
    for (i = 0; i < 16; ++i) {
        c.b[i] = reversePi[a.b[i]];
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

uint128 reverseR(uint128 a) {
    uint128 c;
    unsigned sum = 0;
    int i;
    for (i = 0; i < 15; ++i) {
        sum ^= fastMult(a.b[14 - i], tableForL[i]);
    }
    sum ^= fastMult(a.b[15], tableForL[15]);
    c.b[0] = sum;
    for (i = 0; i < 15; ++i) {
        c.b[15 - i] = a.b[14 - i];
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

uint128 reverseL(uint128 a) {
    uint128 c;
    uint8_t tmp[32];
    uint128 tmpB;
    int i = 0;
    int j = 0;
    memset(tmp, 0, sizeof(uint8_t) * 32);
   // memcpy(tmp, a.b, 16);
    for(i = 0; i < 16; ++i){
        tmp[16 + i] = a.b[i];
    }
    for (i = 0; i < 16; ++i) {
        for (j = 0; j < 16; ++j) {
            tmpB.b[15 - j] = tmp[31 - (j + i)];
        }
        tmp[15 - i] = reverseR(tmpB).b[0];
    }

    for (i = 0; i < 16; ++i) {
        c.b[i] = tmp[i];
    }
    return c;
}

uint128 LSX(uint128 a0, uint128 a1) {
    return L(S(X(a0,a1)));
}

uint128* itConsts() {
    uint128* itConsts = malloc(32*sizeof(uint128));
    int i;
    for (i = 1; i <= 32; ++i) {
        uint128 tmp;
        tmp.qw[0] = i;
        tmp.qw[1] = 0;
        itConsts[i - 1] = L(tmp);
    }
    return itConsts;
}

uint128* F(uint128 c, uint128* k) {
    uint128* itKeys = malloc(2*sizeof(uint128));
    itKeys[1] = k[0];
    itKeys[0] = X(LSX(k[0], c), k[1]);
    return itKeys;
}

uint128** expandKeys(uint128* key256, uint128* itConsts) {
    uint128** Keys = malloc(5*sizeof(uint128*));
    uint128* tmpKey256 = malloc(2*sizeof(uint128));
    Keys[0] = key256;
    memcpy(tmpKey256, key256, 2*sizeof(uint128));
    int i;
    int j;
    for (i = 1; i <= 4; ++i) {
        for (j = 1; j < 8; ++j) {
            tmpKey256 =  F(itConsts[8*(i - 1) + (j - 1)], tmpKey256);
        }
        tmpKey256 =  F(itConsts[8*(i - 1) + 7], tmpKey256);
        Keys[i] = tmpKey256;
    }
    return Keys;
}

uint128 crypto(uint128 a, uint128* k){
    uint128* consts = itConsts();
    uint128** keys = expandKeys(k , consts);
    uint16_t i = 0;
    uint16_t j = 0;
    printf("\n");
    printf("\n");
    printf("\n");
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 2; ++j) {
           a = LSX(keys[i][j], a);
        }
    }
    a = LSX(keys[4][0], a);
    a = X(keys[4][1], a);
    return a;
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
    c = reverseS(c);
    for (i = 0; i < 2; ++i) {
        printf("%016llx", c.qw[1 - i]);
    }
    printf("\n");
    uint128 d;

    d.qw[0] = 0x0000000000000000;
    d.qw[1] = 0xa594000000000000;
    c = R(d);
    for (i = 0; i < 16; ++i) {
        printf("%02x", c.b[15 - i]); //0d64a594000000000000000000000000
    }
    printf("\n");
    c = reverseR(c);
    for (i = 0; i < 16; ++i) {
        printf("%02x", c.b[15 - i]);
    }
    printf("\n");
    uint128 a1;

    a1.qw[0] = 0x8b7b68f66b513c13;
    a1.qw[1] = 0x0e93691a0cfc6040;
    c = L(a1);
    for (i = 0; i < 16; ++i) {
        printf("%02x", c.b[15 - i]);
    }
    printf("\n");
    c = reverseL(c);
    for (i = 0; i < 16; ++i) {
        printf("%02x", c.b[15 - i]);
    }
    printf("\n");
    uint128* k = malloc(2*sizeof(uint128));
    uint128 c1;
    k[0].qw[0] = 0x0011223344556677;
    k[0].qw[1] = 0x8899aabbccddeeff;
    k[1].qw[0] = 0x0123456789abcdef;
    k[1].qw[1] = 0xfedcba9876543210;
    c1.qw[0] = 0x5d27bd10dd849401;
    c1.qw[1] = 0x6ea276726c487ab8;
    c = LSX(k[0], c1);
    for (i = 0; i < 16; ++i) {
        printf("%02x", c.b[15 - i]);
    }
    printf("\n");
    c1.qw[0] = 0x5d27bd10dd849401;
    c1.qw[1] = 0x6ea276726c487ab8;
    uint128* tmp = F(c1, k);
    c = tmp[0];
    for (i = 0; i < 16; ++i) {
        printf("%02x", c.b[15 - i]);
    }
    printf("\n");
    c = tmp[1];
    for (i = 0; i < 16; ++i) {
        printf("%02x", c.b[15 - i]);
    }
    printf("\n");
    printf("___________________________________________");
    printf("\n");
    uint128* tmp2 = itConsts();
    int j;
    for (i = 0; i < 32; ++i) {
        c = tmp2[i];
        for (j = 0; j < 16; ++j) {
            printf("%02x", c.b[15 - j]);
        }
        printf("\n");
    }
    printf("\n");
    printf("___________________________________________");
    printf("\n");
    int z;
    uint128 **keys = expandKeys(k, tmp2);
    for (i = 0; i < 5; ++i) {
        for (j = 0; j < 2; ++j) {
            for (z = 0; z < 16; ++z) {
                printf("%02x", keys[i][j].b[15 - z]);
            }
            printf(" ");
        }
        printf("\n");
    }

    uint128 text;
    text.qw[0] = 0xffeeddccbbaa9988;
    text.qw[1] = 0x1122334455667700;
    text = crypto(text, k);
    printf("\n");
    for (j = 0; j < 16; ++j) {
        printf("%02x", text.b[15 - j]);
    }
    printf("\n");
    return 0;
}