// memory management unit
// Convert memory addresses (virtual addresses) issued by the CPU to physical
// addresses on the bus.
#ifndef MMU_H
#define MMU_H

#include <stdint.h>
#include "dram.h"

uint64_t va2pa(uint64_t vaddr);

#endif