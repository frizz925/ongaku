#ifndef _UTIL_H
#define _UTIL_H

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#ifndef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef max
#define max(a, b) (((a) > (b)) ? (a) : (b))
#endif

static inline void *malloc_copy(const void *src, size_t len) {
    void *dst = malloc(len);
    memcpy(dst, src, len);
    return dst;
}

static inline void *malloc_zero(size_t len) {
    void *ptr = malloc(len);
    memset(ptr, 0, len);
    return ptr;
}

#endif
