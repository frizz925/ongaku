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
    size_t size;
    size_t cap;
    void *buf;
};

size_t ringbuf_sizeof(size_t count, size_t size) {
    return sizeof(ringbuf_t) + (count * size);
}

ringbuf_t *ringbuf_new(size_t count, size_t size) {
    size_t bufsize = ringbuf_sizeof(count, size);
    return ringbuf_init(malloc(bufsize), bufsize, size);
}

ringbuf_t *ringbuf_init(void *buf, size_t bufsize, size_t size) {
    int cap = (bufsize - sizeof(ringbuf_t)) / size;
    assert(cap >= 2);

    ringbuf_t *rb = buf;
    rb->buf = buf + sizeof(ringbuf_t);
    rb->size = size;
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

size_t ringbuf_size(ringbuf_t *rb) {
    return rb->size;
}

size_t ringbuf_capacity(ringbuf_t *rb) {
    return rb->cap;
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
    size_t ridx = (rb->ridx < rb->tidx) ? rb->ridx : 0;
    size_t remaining = ((ridx < rb->widx) ? rb->widx : rb->tidx) - ridx;
    *ptr = rb->buf + (ridx * rb->size);
    rb->ridx = ridx;
    return remaining;
}

size_t ringbuf_writeptr(ringbuf_t *rb, void **ptr, size_t count) {
    *ptr = NULL;
    if (rb->full)
        return 0;
    size_t widx = (rb->widx < rb->cap) ? rb->widx : 0;
    size_t available = ((widx < rb->ridx) ? rb->ridx : rb->cap) - widx;
    if (available < count && widx > rb->ridx) {
        rb->tidx = widx;
        available = rb->ridx;
        widx = 0;
    }
    *ptr = rb->buf + (widx * rb->size);
    rb->widx = widx;
    return available;
}

void ringbuf_advance_readptr(ringbuf_t *rb, size_t off) {
    if (off <= 0)
        return;
    size_t ridx = rb->ridx;
    int diff = rb->widx - ridx;
    ridx += off;
    if (diff > 0) {
        if (ridx >= rb->widx) {
            ridx = rb->widx;
            rb->empty = true;
        }
    } else if (ridx >= rb->tidx)
        ridx = 0;
    rb->ridx = ridx;
    if (rb->full)
        rb->full = false;
}

void ringbuf_advance_writeptr(ringbuf_t *rb, size_t off) {
    if (off <= 0)
        return;
    size_t widx = rb->widx;
    int diff = rb->ridx - widx;
    widx += off;
    if (diff > 0) {
        if (widx >= rb->ridx) {
            widx = rb->ridx;
            rb->full = true;
        }
    } else if (widx >= rb->cap) {
        widx = 0;
        rb->tidx = rb->cap;
    } else if (widx > rb->tidx)
        rb->tidx = widx;
    rb->widx = widx;
    if (rb->empty)
        rb->empty = false;
}

size_t ringbuf_read(ringbuf_t *rb, void *dst, size_t count) {
    if (count <= 0 || rb->empty)
        return 0;
    const void *ptr;
    size_t off = 0;
    while (off < count && ringbuf_remaining(rb) > 0) {
        size_t left = count - off;
        size_t size = ringbuf_readptr(rb, &ptr);
        size_t read = MIN(left, size);
        if (read <= 0)
            break;
        memcpy(dst + (off * rb->size), ptr, read * rb->size);
        off += read;
        ringbuf_advance_readptr(rb, read);
    }
    return off;
}

size_t ringbuf_write(ringbuf_t *rb, const void *src, size_t count) {
    if (count <= 0 || rb->full)
        return 0;
    void *ptr;
    size_t off = 0;
    while (off < count && ringbuf_available(rb) > 0) {
        size_t left = count - off;
        size_t size = ringbuf_writeptr(rb, &ptr, 0);
        size_t write = MIN(left, size);
        if (write <= 0)
            break;
        memcpy(ptr, src + (off * rb->size), write * rb->size);
        off += write;
        ringbuf_advance_writeptr(rb, write);
    }
    return off;
}

void ringbuf_clear(ringbuf_t *rb) {
    rb->full = false;
    rb->empty = true;
    rb->ridx = 0;
    rb->widx = 0;
    rb->tidx = rb->cap;
}

void ringbuf_free(ringbuf_t *rb) {
    free(rb);
}
