#include <cstring>
#include <cstdio>
#include <cstdlib>
#include "common.h"

// convert string to uint64_t
uint64_t string2uint(const char *str, int start, int end) {
    // start: starting index inclusive
    // end: ending index inclusive
    end = (end == -1) ? strlen(str) : end;

    uint64_t value = 0;
    int64_t sign = 1;

    // DFA: `Deterministic Finite Automaton` to scan string and get value
    int state = 0;
    for (int i = start; i < end; ++i) {
        char c = str[i];
        
        if (state == 0) {
            if ('0' == c) {
                state = 1;
                value = 0;
            } else if ('1' <= c && '9' >= c) {
                state = 2;
                value = c - '0';
            } else if ('-' == c) {
                state = 3;
                sign = -1;
            } else if (' ' == c) {
                start = 0;
            } else {
                goto fail;
            }
        } else if (state == 1) {
            if ('1' <= c && '9' >= c) {
                state = 2;
                value = value * 10 + c - '0';
            } else if ('x' == c) {
                state = 4;
            } else if (' ' == c) {
                state = 6;
            } else {
                goto fail;
            }
        } else if (state == 2) {
            if ('1' <= c && '9' >= c) {
                state = 2;
                uint64_t pre_value = value;
                value = value * 10 + c - '0';
                // maybe overflow
                if (pre_value > value) {
                    printf("(int64_t)%s overflow: cannot convert\n", str);
                    goto fail;
                }
            } else if (' ' == c) {
                state = 6;
            } else {
                goto fail;
            }
        } else if (state == 3) {
            if ('0' == c) {
                state = 1;
            } else if ('1' <= c && '9' >= c) {
                value = c - '0';
                state = 2;
            } else {
                goto fail;
            }
        } else if (state == 4) {
            if ('0' <= c && '9' >= c) {
                state = 5;
                value = value * 16 + c - '0';
            } else if ('a' <= c && 'f' >= c) {
                state = 5;
                value = value * 16 + c - 'a' + 10;
            } else {
                goto fail;
            }
        } else if (state == 5) {
            // hex
            if ('0' <= c && '9' >= c) {
                uint64_t pre_value = value;
                state = 5;
                value = value * 16 + c - '0';
                // maybe overflow
                if (pre_value > value) {
                    printf("(int64_t)%s overflow: cannot convert\n", str);
                    goto fail;
                }
            } else if ('a' <= c && 'f' >= c) {
                uint64_t pre_value = value;
                state = 5;
                value = value * 16 + c - 'a' + 10;
                // maybe overflow
                if (pre_value > value) {
                    printf("(uint64_t)%s overflow: cannot convert\n", str);
                    goto fail;
                }
            } else {
                goto fail;
            }
        } else if (state == 6) {
            if (' ' == c) {
                state = 6;
            } else {
                goto fail;
            }
        }
    }

    return sign * value;

    fail:
    printf("type converter: <%s> cannot be converted to integer\n", str);
    exit(0);
}