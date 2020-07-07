#include <stdio.h>

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

unsigned getRemainder(unsigned dividend, unsigned divisor) {
    unsigned tmpDivisor = 0;
    while (dividend >= divisor) {
        tmpDivisor = divisor;
        while (((dividend ^ tmpDivisor) >= dividend || ((dividend ^ tmpDivisor) >= tmpDivisor)))
            tmpDivisor <<= 1;
        dividend ^= tmpDivisor;
    }
    return dividend;
}

unsigned summ(unsigned a, unsigned b) {
    return a ^ b;
}

unsigned mul(unsigned a, unsigned b, unsigned p) {
    unsigned x = 0;
    while (b != 0) {
        if ((b & 0x1) == 0x1)
            x ^= a;
        b >>= 1;
        a <<= 1;
    }
    return getRemainder(x, p);
}

int main() {

    printf("%x\n", mul(83, 9, 0b111000011));
    printf("%x", summ(83, 9));
    return 0;
}