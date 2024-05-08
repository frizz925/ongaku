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
    atomic_size_t tidx;
    size_t cap;
    void *buf;
};

size_t ringbuf_sizeof(size_t size) {
    return sizeof(ringbuf_t) + size;
}

ringbuf_t *ringbuf_new(size_t size) {
    size_t bufsize = ringbuf_sizeof(size);
    return ringbuf_init(malloc(bufsize), bufsize);
}

ringbuf_t *ringbuf_init(void *buf, size_t bufsize) {
    int cap = bufsize - sizeof(ringbuf_t);
    assert(cap >= 4);

    ringbuf_t *rb = buf;
    rb->buf = buf + bufsize - cap;
    rb->cap = cap;
    ringbuf_clear(rb);
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
        return rb->tidx;
    return (rb->widx > rb->ridx) ? (rb->widx - rb->ridx) : (rb->tidx - rb->ridx + rb->widx);
}

size_t ringbuf_available(ringbuf_t *rb) {
    if (rb->full)
        return 0;
    if (rb->empty)
        return rb->cap;
    return (rb->ridx > rb->widx) ? (rb->ridx - rb->widx) : (rb->cap - rb->widx + rb->ridx);
}

size_t ringbuf_readptr(ringbuf_t *rb, const void **ptr) {
    *ptr = NULL;
    if (rb->empty)
        return 0;
    *ptr = rb->buf + rb->ridx;
    return ((rb->ridx < rb->widx) ? rb->widx : rb->tidx) - rb->ridx;
}

size_t ringbuf_writeptr(ringbuf_t *rb, void **ptr, size_t size) {
    *ptr = NULL;
    if (rb->full || size > rb->cap)
        return 0;
    if (rb->widx >= rb->cap)
        rb->widx = 0;
    size_t available = ((rb->widx < rb->ridx) ? rb->ridx : rb->cap) - rb->widx;
    if (size > 0 && available < size) {
        if (rb->widx <= rb->ridx)
            return 0;
        rb->tidx = rb->widx;
        rb->widx = 0;
        available = rb->ridx;
    }
    *ptr = rb->buf + rb->widx;
    return available;
}

void ringbuf_advance_readptr(ringbuf_t *rb, size_t off) {
    if (off <= 0)
        return;
    size_t ridx = rb->ridx;
    if (ridx + off >= rb->tidx)
        ridx = 0;
    else
        ridx += off;
    if (ridx == rb->widx)
        rb->empty = true;
    rb->ridx = ridx;
    if (rb->full)
        rb->full = false;
}

void ringbuf_advance_writeptr(ringbuf_t *rb, size_t off) {
    if (off <= 0)
        return;
    size_t widx = rb->widx;
    if (widx + off >= rb->cap) {
        widx = 0;
        rb->tidx = rb->cap;
    } else
        widx += off;
    if (rb->ridx == widx)
        rb->full = true;
    rb->widx = widx;
    if (rb->empty)
        rb->empty = false;
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
        size_t size = ringbuf_writeptr(rb, &ptr, 0);
        size_t write = min(left, size);
        if (write <= 0)
            break;
        memcpy(ptr, src + off, write);
        off += write;
        ringbuf_advance_writeptr(rb, write);
    }
    return off;
}

void ringbuf_clear(ringbuf_t *rb) {
    rb->ridx = 0;
    rb->widx = 0;
    rb->tidx = rb->cap;
    rb->full = rb->cap <= 0;
    rb->empty = !rb->full;
}

void ringbuf_free(ringbuf_t *rb) {
    free(rb);
}
