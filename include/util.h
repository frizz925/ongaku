#ifndef _UTIL_H
#define _UTIL_H

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

#define SET_MESSAGE(ptr, message) \
    if (ptr != NULL) \
    *ptr = message

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

static inline size_t memwrite(void *dst, const void *src, size_t len) {
    memcpy(dst, src, len);
    return len;
}

#endif
