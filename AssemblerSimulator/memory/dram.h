#ifndef DRAM_H
#define DRAM_H

#include <stdio.h>
#include <stdint.h>
#include "register.h"
#include "mmu.h"

#define MM_LEN 1000
extern uint8_t mm[MM_LEN];

uint64_t read64bits_dram(uint64_t paddr);
void write64bits_dram(uint64_t paddr, uint64_t data);
void print_register();
void print_stack();

#endif