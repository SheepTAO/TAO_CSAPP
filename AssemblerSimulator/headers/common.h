#ifndef COMMON_H
#define COMMON_H

#include <cstdint>

using std::uint64_t;

#define DEBUG_INSTRUCTIONCYCLE  0x1
#define DEBUG_REGISTERS         0x2
#define DEBUG_PRINTSTACK        0x4
#define DEBUG_CACHEDETAILS      0x10
#define DEBUG_MMU               0x20
#define DEBUG_LINKER            0x40
#define DEBUG_LOADER            0x80
#define DEBUG_PARSEINST         0x100

#define DEBUG_VERBOSE_SET       0x1

// do page walk
#define DEBUG_ENABLE_PAGE_WALK  0

// use sram cache for memory access
#define DEBUG_ENABLE_SRAM_CACHE 0

uint64_t debug_printf(uint64_t openSet, const char *format, ...);

#endif
