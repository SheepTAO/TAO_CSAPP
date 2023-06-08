#include <iostream>
#include <cstdarg>
#include "common.h"

uint64_t debug_printf(uint64_t openSet, const char *format, ...) {
    if ((openSet & DEBUG_VERBOSE_SET) == 0x0) {
        return 0x1;
    }

    // implementation of std printf()
    va_list argptr;
    va_start(argptr, format);
    vfprintf(stderr, format, argptr);
    va_end(argptr);

    return 0x0;
}