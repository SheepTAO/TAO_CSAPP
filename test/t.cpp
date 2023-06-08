#include <cstdint>
#include <cstdio>

uint32_t uint2float(uint32_t u) {
    if (u == 0x0) {
        return 0x0;
    }

    uint32_t f, e;
    uint32_t s = 0x80000000 & u;
    u &= 0x7fffffff;

    int n = 0;
    for (int i = 0; i < 31; ++i) {
        if (u >> i == 0x1) {
            n = i;
            break;
        }
    }

    if (n <= 23) {
        // no near
        f = u & (0xffffffff >> (32 - n));
        e = n + 127;

        return s | (e << 23) | f;
    } else {
        // should near
    
    }

    return 0;
}

int main() {
    uint32_t u = 0x00b7800;
    uint2float(u);

    return 0;
}