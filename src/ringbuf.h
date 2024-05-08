#include <stddef.h>

typedef struct ringbuf ringbuf_t;

size_t ringbuf_sizeof(size_t size);
ringbuf_t *ringbuf_new(size_t size);
ringbuf_t *ringbuf_init(void *buf, size_t bufsize);
int ringbuf_empty(ringbuf_t *rb);
int ringbuf_full(ringbuf_t *rb);
size_t ringbuf_remaining(ringbuf_t *rb);
size_t ringbuf_available(ringbuf_t *rb);
size_t ringbuf_readptr(ringbuf_t *rb, const void **ptr);
size_t ringbuf_writeptr(ringbuf_t *rb, void **ptr, size_t size);
void ringbuf_advance_readptr(ringbuf_t *rb, size_t off);
void ringbuf_advance_writeptr(ringbuf_t *rb, size_t off);
size_t ringbuf_read(ringbuf_t *rb, void *dst, size_t len);
size_t ringbuf_write(ringbuf_t *rb, const void *src, size_t len);
void ringbuf_clear(ringbuf_t *rb);
void ringbuf_free(ringbuf_t *rb);
