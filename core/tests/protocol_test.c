#include "protocol.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define SAMPLE_CONTENT "This is a sample content"

int main() {
    char buf[128];
    size_t len, wlen, rlen;
    const size_t clen = sizeof(SAMPLE_CONTENT);

    wlen = packet_data_size_write(buf, sizeof(buf), clen);
    rlen = packet_data_size_read(buf, wlen, &len);
    assert(rlen == wlen);
    assert(len == clen);

    wlen = packet_data_write(buf, sizeof(buf), SAMPLE_CONTENT, clen);
    rlen = packet_data_read(buf, wlen, buf, sizeof(buf));
    assert(rlen == wlen);
    assert(memcmp(buf, SAMPLE_CONTENT, len) == 0);

    return EXIT_SUCCESS;
}
