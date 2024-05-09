#include "pool.h"
#include <assert.h>

#define MAX_CAPACITY 5

typedef struct {
    int idx;
    int assigned;
} pool_item_t;

static void test_pool(size_t cap) {
    pool_t pool;
    pool_init(&pool, sizeof(pool_item_t), cap);

    for (int i = 0; i < MAX_CAPACITY; i++) {
        pool_item_t *item = pool_get(&pool);

        assert(item != NULL);
        if (cap > 0 && i < cap) {
            assert(!item->assigned);
            assert(item->idx == 0);
        } else if (i > 0)
            assert(item->assigned);

        item->idx = i;
        item->assigned = 1;
        pool_put(&pool, item);
    }

    pool_deinit(&pool);
}

int main() {
    test_pool(0);
    test_pool(MAX_CAPACITY / 2);
    test_pool(MAX_CAPACITY);
}
