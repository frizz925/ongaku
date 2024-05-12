#include "crypto/crypto.h"
#include "util.h"

#include <assert.h>
#include <string.h>

#ifdef _WIN32
#else
#include <arpa/inet.h>
#endif

static size_t plaintext_key_exchange(void *handle, const char *key, size_t keylen, int *err, const char **message) {
    SET_MESSAGE(message, NULL);
    *err = 0;
    return 0;
}

static size_t plaintext_encrypt(void *handle, const char *src, size_t srclen, char *dst, size_t dstlen) {
    assert(dstlen >= srclen);
    if (src != dst)
        memcpy(dst, src, srclen);
    return srclen;
}

static size_t plaintext_decrypt(void *handle,
                                const char *src,
                                size_t srclen,
                                char *dst,
                                size_t *dstlen,
                                int *err,
                                const char **message) {
    *err = 0;
    if (srclen > *dstlen) {
        SET_MESSAGE(message, "Destination buffer too small");
        *err = -1;
        return 0;
    }
    if (src != dst)
        memcpy(dst, src, srclen);
    *dstlen = srclen;
    return srclen;
}

void crypto_init_plaintext(crypto_t *c) {
    memset(c, 0, sizeof(crypto_t));
    c->key_exchange = plaintext_key_exchange;
    c->encrypt = plaintext_encrypt;
    c->decrypt = plaintext_decrypt;
}
