#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <stdint.h>

unsigned getBinaryLenght(unsigned num){
    unsigned count = 1;
    while(num > 1){
        num /= 2;
        ++count;
    }
    return count;
}
unsigned getRemainder(unsigned int dividend, unsigned int divisor) {
    unsigned tmpDivisor = 0;
    while (dividend >= divisor) {
        tmpDivisor = divisor;
        tmpDivisor <<= getBinaryLenght(dividend) - getBinaryLenght(tmpDivisor);
        dividend ^= tmpDivisor;
    }
    return dividend;
}

unsigned summ(unsigned a, unsigned b, unsigned p) {
    return  getRemainder(a^b, p);
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
