#ifndef _CRYPTO_H
#define _CRYPTO_H

#include "util.h"

#include <stddef.h>

typedef struct crypto {
    size_t (*pubkey_size)(void *handle);
    const char *(*pubkey)(void *handle, size_t *len);
    int (*key_exchange)(void *handle, const char *key, size_t keylen, const char **message);
    size_t (*encrypt)(void *handle, const char *src, size_t srclen, char *dst, size_t dstlen);
    int (*decrypt)(void *handle, const char *src, size_t srclen, char *dst, size_t *dstlen, const char **message);
    void (*deinit)(void *handle);
    void *handle;
} crypto_t;

static int not_implemented(const char **message) {
    SET_MESSAGE(message, "Not implemented");
    return -1;
}

static inline size_t crypto_pubkey_size(crypto_t *c) {
    return (c->pubkey_size != NULL) ? c->pubkey_size(c->handle) : 0;
}

static inline const char *crypto_pubkey(crypto_t *c, size_t *len) {
    *len = 0;
    return (c->pubkey != NULL) ? c->pubkey(c->handle, len) : NULL;
}

static inline int crypto_key_exchange(crypto_t *c, const char *key, size_t keylen, const char **message) {
    return (c->key_exchange != NULL) ? c->key_exchange(c->handle, key, keylen, message) : not_implemented(message);
}

static inline size_t crypto_encrypt(crypto_t *c, const char *src, size_t srclen, char *dst, size_t dstlen) {
    return (c->encrypt != NULL) ? c->encrypt(c->handle, src, srclen, dst, dstlen) : 0;
}

static inline int crypto_decrypt(crypto_t *c,
                                 const char *src,
                                 size_t srclen,
                                 char *dst,
                                 size_t *dstlen,
                                 const char **message) {
    return (c->decrypt != NULL) ? c->decrypt(c->handle, src, srclen, dst, dstlen, message) : not_implemented(message);
}

static inline void crypto_deinit(crypto_t *c) {
    if (c->deinit != NULL)
        c->deinit(c->handle);
}

#endif
