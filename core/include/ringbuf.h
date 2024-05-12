#ifndef _RINGBUF_H
#define _RINGBUF_H

#include <stddef.h>

typedef struct ringbuf ringbuf_t;

size_t ringbuf_sizeof(size_t count, size_t size);
ringbuf_t *ringbuf_new(size_t count, size_t size);
ringbuf_t *ringbuf_init(void *buf, size_t bufsize, size_t size);
int ringbuf_empty(ringbuf_t *rb);
int ringbuf_full(ringbuf_t *rb);
size_t ringbuf_size(ringbuf_t *rb);
size_t ringbuf_capacity(ringbuf_t *rb);
size_t ringbuf_remaining(ringbuf_t *rb);
size_t ringbuf_available(ringbuf_t *rb);
size_t ringbuf_readptr(ringbuf_t *rb, const void **ptr);
size_t ringbuf_writeptr(ringbuf_t *rb, void **ptr, size_t count);
void ringbuf_commit_read(ringbuf_t *rb, size_t off);
void ringbuf_commit_write(ringbuf_t *rb, size_t off);
size_t ringbuf_read(ringbuf_t *rb, void *dst, size_t count);
size_t ringbuf_write(ringbuf_t *rb, const void *src, size_t count);
void ringbuf_clear(ringbuf_t *rb);
void ringbuf_free(ringbuf_t *rb);

#endif
