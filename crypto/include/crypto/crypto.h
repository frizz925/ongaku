#ifndef _CRYPTO_H
#define _CRYPTO_H

#include <stddef.h>

typedef struct crypto {
    size_t (*write_pubkey)(void *handle, char *dst, size_t len);
    size_t (*key_exchange)(void *handle, const char *key, size_t keylen, int *err, const char **message);
    size_t (*encrypt)(void *handle,
                      const char *src,
                      size_t srclen,
                      char *dst,
                      size_t dstlen,
                      int *err,
                      const char **message);
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

static inline size_t crypto_write_pubkey(crypto_t *c, char *dst, size_t len) {
    return c->write_pubkey(c->handle, dst, len);
}

static inline size_t crypto_key_exchange(crypto_t *c, const char *key, size_t keylen, int *err, const char **message) {
    return c->key_exchange(c->handle, key, keylen, err, message);
}

static inline size_t crypto_encrypt(crypto_t *c,
                                    const char *src,
                                    size_t srclen,
                                    char *dst,
                                    size_t dstlen,
                                    int *err,
                                    const char **message) {
    return c->encrypt(c->handle, src, srclen, dst, dstlen, err, message);
}

static inline size_t crypto_decrypt(crypto_t *c,
                                    const char *src,
                                    size_t srclen,
                                    char *dst,
                                    size_t *dstlen,
                                    int *err,
                                    const char **message) {
    return c->decrypt(c->handle, src, srclen, dst, dstlen, err, message);
}

static inline void crypto_deinit(crypto_t *c) {
    return c->deinit(c);
}

#endif
