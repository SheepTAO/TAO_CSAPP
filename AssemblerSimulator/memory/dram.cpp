#include "dram.h"

#define SRAM_CACHE_SETTING 0

uint8_t mm[MM_LEN];

uint64_t read64bits_dram(uint64_t paddr) {
    if (SRAM_CACHE_SETTING == 1) {
        return 0x0;
    }

    uint64_t val = 0x0;
    for (int i = 7; i >= 0; --i) {
        val += (uint64_t)mm[paddr + i];
        if (i > 0) {
            val <<= 8;
        }
    }

    return val;
}

void write64bits_dram(uint64_t paddr, uint64_t data) {
    if (SRAM_CACHE_SETTING == 1) {
        return;
    }

    for (uint64_t i = 0; i < 8; ++i) {
        mm[paddr + i] = data & 0xff;
        data >>= 8;
    }
}

void print_register() {
    printf("rax = %16lx\trbx = %16lx\trcx = %16lx\trdx = %16lx\n",
        reg.rax, reg.rbx, reg.rcx, reg.rdx);
    printf("rsi = %16lx\trdi = %16lx\trbp = %16lx\trsp = %16lx\n",
        reg.rsi, reg.rdi, reg.rbp, reg.rsp);
    printf("rip = %16lx\n", reg.rip);
}

void print_stack() {
    uint64_t rsp = va2pa(reg.rsp);
    uint64_t rbp = va2pa(reg.rbp);

    while (rsp < rbp) {
        
    }
}