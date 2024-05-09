#include "pool.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>

struct pool_element {
    pool_element_t *next;
};

const size_t sz_element = sizeof(pool_element_t);

void pool_init(pool_t *pool, size_t size, size_t capacity) {
    pool->capacity = capacity;
    pool->blocksize = sz_element + size;
    pool->base = pool->head = (pool_element_t *)(capacity > 0 ? calloc(capacity, pool->blocksize) : NULL);
    pool->tail = NULL;

    pool_element_t *cur = pool->head;
    for (int i = 0; i < capacity; i++) {
        pool->tail = cur;
        cur = cur->next = (void *)cur + pool->blocksize;
    }
    if (pool->tail)
        pool->tail->next = NULL;
}

void *pool_get(pool_t *pool) {
    void *ptr;
    if (pool->head) {
        ptr = pool->head;
        pool->head = pool->head->next;
        if (!pool->head)
            pool->tail = NULL;
    } else if (!pool->base) {
        /* Only allocate new memory if we don't have contiguous memory allocation */
        ptr = malloc_zero(pool->blocksize);
    } else
        return NULL;
    return ptr + sz_element;
}

void pool_put(pool_t *pool, void *ptr) {
    pool_element_t *cur = (pool_element_t *)(ptr - sz_element);
    pool_element_t *prev = pool->tail != NULL ? pool->tail : pool->head;
    cur->next = NULL;
    if (prev)
        prev->next = cur;
    pool->tail = cur;
    if (!pool->head)
        pool->head = prev != NULL ? prev : cur;
}

void pool_deinit(pool_t *pool) {
    /* Free every dynamically allocated memory if we don't have contiguous memory allocation */
    if (!pool->base) {
        pool_element_t *cur = pool->head;
        while (cur != NULL) {
            void *ptr = cur;
            cur = cur->next;
            free(ptr);
        }
    } else
        free(pool->base);

    pool->blocksize = 0;
    pool->capacity = 0;
    pool->base = pool->head = pool->tail = NULL;
}
