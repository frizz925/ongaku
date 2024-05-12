#include "ringbuf.h"

#include <assert.h>
#include <string.h>

int main() {
    int values[] = {1, 2, 3, 4, 5};
    int value, base, *ptr;
    size_t size, req, cap = sizeof(values) / sizeof(int);
    ringbuf_t *rb = ringbuf_new(cap, sizeof(int));

    for (value = 0; value < cap - 1; value++)
        assert(ringbuf_write(rb, &value, 1) == 1);

    for (int i = 0; i < cap - 1; i++) {
        assert(ringbuf_read(rb, &value, 1) == 1);
        assert(value == i);
    }

    req = 2;
    size = ringbuf_writeptr(rb, (void *)&ptr, req);
    assert(size >= req);

    base = 10;
    for (value = base; value < base + req; value++)
        *ptr++ = value;
    ringbuf_commit_write(rb, req);

    size = ringbuf_readptr(rb, (void *)&ptr);
    assert(size == req);

    for (int i = base; i < base + size; i++)
        assert(*ptr++ == i);
    ringbuf_commit_read(rb, size);

    assert(ringbuf_empty(rb));
    assert(ringbuf_available(rb) == cap);
    assert(ringbuf_remaining(rb) == 0);

    assert(ringbuf_write(rb, values, cap) == cap);

    assert(ringbuf_full(rb));
    assert(ringbuf_available(rb) == 0);
    assert(ringbuf_remaining(rb) == cap);

    memset(values, 0, sizeof(values));
    assert(ringbuf_read(rb, values, cap) == cap);

    base = 1;
    for (int i = 0; i < cap; i++)
        assert(values[i] == i + base);

    ringbuf_free(rb);
}
