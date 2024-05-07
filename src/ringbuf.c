#include "ringbuf.h"
#include "util.h"

#include <assert.h>
#include <stdatomic.h>
#include <stdbool.h>

#define MIN_BUFSIZE 4

struct ringbuf {
    atomic_bool full;
    atomic_bool empty;
    atomic_size_t ridx;
    atomic_size_t widx;
    size_t capacity;
    void *buf;
};

ringbuf_t *ringbuf_init(void *base, size_t len) {
    int capacity = len - sizeof(ringbuf_t);
    assert(capacity >= 4);

    ringbuf_t *rb = base;
    rb->full = false;
    rb->empty = true;
    rb->ridx = 0;
    rb->widx = 0;
    rb->capacity = capacity;
    rb->buf = base + len - capacity;
    return rb;
}

int ringbuf_empty(ringbuf_t *rb) {
    return rb->empty;
}

int ringbuf_full(ringbuf_t *rb) {
    return rb->full;
}

size_t ringbuf_remaining(ringbuf_t *rb) {
    if (rb->empty)
        return 0;
    if (rb->full)
        return rb->capacity;
    return (rb->widx > rb->ridx) ? (rb->widx - rb->ridx) : (rb->capacity - ringbuf_available(rb));
}

size_t ringbuf_available(ringbuf_t *rb) {
    if (rb->full)
        return 0;
    if (rb->empty)
        return rb->capacity;
    return (rb->ridx > rb->widx) ? (rb->ridx - rb->widx) : (rb->capacity - ringbuf_remaining(rb));
}

size_t ringbuf_readptr(ringbuf_t *rb, const void **ptr) {
    if (rb->empty) {
        *ptr = NULL;
        return 0;
    }
    *ptr = rb->buf + rb->ridx;
    return ((rb->ridx <= rb->widx) ? rb->widx : rb->capacity) - rb->ridx;
}

size_t ringbuf_writeptr(ringbuf_t *rb, void **ptr) {
    if (rb->full) {
        *ptr = NULL;
        return 0;
    }
    if (rb->widx >= rb->capacity)
        rb->widx = 0;
    *ptr = rb->buf + rb->widx;
    return ((rb->widx < rb->ridx) ? rb->ridx : rb->capacity) - rb->widx;
}

void ringbuf_advance_readptr(ringbuf_t *rb, size_t off) {
    if (off <= 0)
        return;
    if (rb->ridx + off >= rb->capacity)
        rb->ridx = 0;
    else
        rb->ridx += off;
    if (rb->full)
        rb->full = false;
    if (rb->ridx == rb->widx)
        rb->empty = true;
}
void ringbuf_advance_writeptr(ringbuf_t *rb, size_t off) {
    if (off <= 0)
        return;
    if (rb->widx + off >= rb->capacity)
        rb->widx = 0;
    else
        rb->widx += off;
    if (rb->empty)
        rb->empty = false;
    if (rb->ridx == rb->widx)
        rb->full = true;
}

size_t ringbuf_read(ringbuf_t *rb, void *dst, size_t len) {
    if (len <= 0 || rb->empty)
        return 0;
    const void *ptr;
    size_t off = 0;
    while (off < len && ringbuf_remaining(rb) > 0) {
        size_t left = len - off;
        size_t size = ringbuf_readptr(rb, &ptr);
        size_t read = min(left, size);
        if (read <= 0)
            break;
        memcpy(dst + off, ptr, read);
        off += read;
        ringbuf_advance_readptr(rb, read);
    }
    return off;
}

size_t ringbuf_write(ringbuf_t *rb, const void *src, size_t len) {
    if (len <= 0 || rb->full)
        return 0;
    void *ptr;
    size_t off = 0;
    while (off < len && ringbuf_available(rb) > 0) {
        size_t left = len - off;
        size_t size = ringbuf_writeptr(rb, &ptr);
        size_t write = min(left, size);
        if (write <= 0)
            break;
        memcpy(ptr, src + off, write);
        off += write;
        ringbuf_advance_writeptr(rb, write);
    }
    return off;
}
