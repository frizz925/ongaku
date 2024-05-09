#ifndef _POOL_H
#define _POOL_H

#include <stddef.h>

typedef struct pool_element pool_element_t;

typedef struct pool {
    pool_element_t *base, *head, *tail;
    size_t blocksize;
    size_t capacity;
} pool_t;

void pool_init(pool_t *pool, size_t size, size_t capacity);
void *pool_get(pool_t *pool);
void pool_put(pool_t *pool, void *ptr);
void pool_deinit(pool_t *pool);

#endif
