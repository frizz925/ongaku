#include <stddef.h>

typedef struct ringbuf ringbuf_t;

ringbuf_t *ringbuf_init(void *base, size_t len);
int ringbuf_empty(ringbuf_t *rb);
int ringbuf_full(ringbuf_t *rb);
size_t ringbuf_remaining(ringbuf_t *rb);
size_t ringbuf_available(ringbuf_t *rb);
size_t ringbuf_readptr(ringbuf_t *rb, const void **ptr);
size_t ringbuf_writeptr(ringbuf_t *rb, void **ptr);
void ringbuf_advance_readptr(ringbuf_t *rb, size_t off);
void ringbuf_advance_writeptr(ringbuf_t *rb, size_t off);
size_t ringbuf_read(ringbuf_t *rb, void *dst, size_t len);
size_t ringbuf_write(ringbuf_t *rb, const void *src, size_t len);
