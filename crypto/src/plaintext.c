#include "crypto/crypto.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

static size_t plaintext_write_pubkey(void *handle, char *dst, size_t len) {
    return 0;
}

static size_t plaintext_key_exchange(void *handle, const char *key, size_t keylen, int *err, const char **message) {
    *err = 0;
    return 0;
}

static size_t plaintext_encrypt(void *handle,
                                const char *src,
                                size_t srclen,
                                char *dst,
                                size_t dstlen,
                                int *err,
                                const char **message) {
    *err = 0;
    assert(srclen <= dstlen);
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
    assert(srclen <= *dstlen);
    if (src != dst)
        memcpy(dst, src, srclen);
    return srclen;
}

static void plaintext_deinit(void *handle) {}

void crypto_init_plaintext(crypto_t *c) {
    c->write_pubkey = plaintext_write_pubkey;
    c->key_exchange = plaintext_key_exchange;
    c->encrypt = plaintext_encrypt;
    c->decrypt = plaintext_decrypt;
    c->deinit = plaintext_deinit;
    c->handle = NULL;
}
