#ifndef _CRYPTO_H
#define _CRYPTO_H

#include <stddef.h>

typedef struct crypto {
    size_t (*pubkey_size)(void *handle);
    const char *(*pubkey)(void *handle, size_t *len);
    size_t (*key_exchange)(void *handle, const char *key, size_t keylen, int *err, const char **message);
    size_t (*encrypt)(void *handle, const char *src, size_t srclen, char *dst, size_t dstlen);
    size_t (*decrypt)(void *handle,
                      const char *src,
                      size_t srclen,
                      char *dst,
                      size_t *dstlen,
                      int *err,
                      const char **message);
    void (*deinit)(void *handle);
    void *handle;
} crypto_t;

static size_t not_implemented(int *err, const char **message) {
    *err = -1;
    *message = "Not implemented";
    return 0;
}

static inline size_t crypto_pubkey_size(crypto_t *c) {
    return (c->pubkey_size != NULL) ? c->pubkey_size(c->handle) : 0;
}

static inline const char *crypto_pubkey(crypto_t *c, size_t *len) {
    *len = 0;
    return (c->pubkey != NULL) ? c->pubkey(c->handle, len) : NULL;
}

static inline size_t crypto_key_exchange(crypto_t *c, const char *key, size_t keylen, int *err, const char **message) {
    return (c->key_exchange != NULL) ? c->key_exchange(c->handle, key, keylen, err, message)
                                     : not_implemented(err, message);
}

static inline size_t crypto_encrypt(crypto_t *c, const char *src, size_t srclen, char *dst, size_t dstlen) {
    return (c->encrypt != NULL) ? c->encrypt(c->handle, src, srclen, dst, dstlen) : 0;
}

static inline size_t crypto_decrypt(crypto_t *c,
                                    const char *src,
                                    size_t srclen,
                                    char *dst,
                                    size_t *dstlen,
                                    int *err,
                                    const char **message) {
    return (c->decrypt != NULL) ? c->decrypt(c->handle, src, srclen, dst, dstlen, err, message)
                                : not_implemented(err, message);
}

static inline void crypto_deinit(crypto_t *c) {
    if (c->deinit != NULL)
        c->deinit(c->handle);
}

#endif
