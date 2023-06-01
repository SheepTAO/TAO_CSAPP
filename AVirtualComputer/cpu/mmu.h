// memory management unit
// Convert memory addresses (virtual addresses) issued by the CPU to physical
// addresses on the bus.

#include <stdint.h>

uint64_t va2pa(uint64_t vaddr);