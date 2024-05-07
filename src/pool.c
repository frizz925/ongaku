#include "pool.h"

#include <stdlib.h>
#include <string.h>

struct pool_element {
    pool_element_t *next;
};

const size_t sz_element = sizeof(pool_element_t);

void pool_init(pool_t *pool, size_t size, size_t capacity) {
    pool->length = capacity;
    pool->capacity = capacity;
    pool->blocksize = sz_element + size;
    pool->base = pool->head = (pool_element_t *)(capacity > 0 ? calloc(capacity, pool->blocksize) : NULL);

    pool_element_t *cur = pool->head;
    for (int i = 0; i < capacity; i++)
        cur = cur->next = (void *)cur + pool->blocksize;
    if (cur) {
        cur->next = NULL;
        pool->tail = cur;
    }
}

void *pool_get(pool_t *pool) {
    if (pool->head) {
        void *ptr = (void *)pool->head + sz_element;
        pool->head = pool->head->next;
        if (!pool->head)
            pool->tail = NULL;
        pool->length--;
        return ptr;
    }
    /* Don't allocate new memory if we already have contiguous memory allocation */
    if (pool->base)
        return NULL;
    void *ptr = malloc(pool->blocksize);
    memset(ptr, 0, pool->blocksize);
    return ptr + sz_element;
}

void pool_put(pool_t *pool, void *ptr) {
    pool_element_t *cur = (pool_element_t *)(ptr - sz_element);
    pool_element_t *prev = pool->tail;
    cur->next = NULL;
    if (prev)
        prev->next = cur;
    pool->tail = cur;
    if (!pool->head)
        pool->head = pool->tail;
    pool->length++;
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
    pool->head = pool->tail = NULL;
}
