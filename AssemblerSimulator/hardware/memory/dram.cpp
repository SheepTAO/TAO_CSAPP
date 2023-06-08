// Dynamic Random Access Memory
#include "cpu.h"
#include "memory.h"
#include "common.h"

// memory accessing used in instructions
uint64_t read64bits_dram(uint64_t paddr, core_t *cr) {
    if (DEBUG_ENABLE_SRAM_CACHE == 1) {
        // try to load uint64_t from SRAM cache
        // little-endian
    } else {
        // read from DRAM directly
        // little-endian
        uint64_t val = 0x0;

        for (int i = 7; i >= 0; --i) {
            val += (uint64_t)pm[paddr + i];
            if (i > 0) {
                val <<= 8;
            }
        }

        return val;
    }
}

void write64bits_dram(uint64_t paddr, uint64_t data, core_t *cr) {
    if (DEBUG_ENABLE_SRAM_CACHE == 1) {
        // try to write uint64_t to SRAM cache
        // little-endian
    } else {
        // write to DRAM directly
        // little-endian
        for (int i = 0; i < 8; ++i) {
            pm[paddr + i] = (data >> i * 8) & 0xff; 
        }
    }
}