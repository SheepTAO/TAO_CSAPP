// Dynamic Random Access Memory
#include <cstring>
#include <cassert>
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

void readinst_dram(uint64_t paddr, char *buf, core_t *cr) {
    for (int i = 0; i < MAX_INSTRUCTION_CHAR; ++i) {
        buf[i] = pm[paddr + i];
    }
}

void writeinst_darm(uint64_t paddr, const char *str, core_t *cr) {
    int str_len = strlen(str);
    assert(str_len < MAX_INSTRUCTION_CHAR);

    for (int i = 0; i < str_len; ++i) {
        pm[paddr + i] = str[i];
    }
}