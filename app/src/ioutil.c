#include "ioutil.h"
#include "util.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

#ifdef _WIN32
#else
#include <arpa/inet.h>
#endif

size_t ioutil_encrypt(crypto_t *crypto, char *dst, size_t dstlen, const char *src, size_t srclen) {
    uint16_t *size = (uint16_t *)dst;
    char *buf = (char *)(size + 1);
    char *tail = dst + dstlen;
    assert(buf < tail);
    assert(tail - buf >= srclen);

    if (dst == src) {
        memmove(buf, src, srclen);
        src = buf;
    }
    size_t len = crypto_encrypt(crypto, src, srclen, buf, tail - buf);
    *size = htons(len);

    return buf - dst + len;
}

int ioutil_decrypt(crypto_t *crypto, const char *src, size_t srclen, char *dst, size_t *dstlen, const char **message) {
    const uint16_t *size = (uint16_t *)src;
    const char *buf = (char *)(size + 1);
    const char *tail = src + srclen;
    if (buf >= tail) {
        SET_MESSAGE(message, "Source buffer too small for header");
        return -1;
    }

    size_t len = ntohs(*size);
    if (buf + len > tail) {
        SET_MESSAGE(message, "Source buffer too small for message");
        return -1;
    }

    int res = crypto_decrypt(crypto, buf, len, dst, dstlen, message);
    if (res < 0) {
        SET_MESSAGE(message, "Decryption failed");
        return -1;
    }

    return buf - src + res;
}
