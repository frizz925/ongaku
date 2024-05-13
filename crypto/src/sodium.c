#include "crypto/crypto.h"
#include "util.h"

#include <assert.h>
#include <sodium.h>

#define NONCE_WINDOW_SIZE 65536

typedef struct {
    unsigned char pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char sk[crypto_kx_PUBLICKEYBYTES];
    unsigned char rx[crypto_kx_SESSIONKEYBYTES];
    unsigned char tx[crypto_kx_SESSIONKEYBYTES];
    unsigned char rx_nonce[crypto_secretbox_NONCEBYTES];
    unsigned char tx_nonce[crypto_secretbox_NONCEBYTES];
    int server;
} sodium_t;

static void nonce_increment(unsigned char *nonce) {
    for (int i = crypto_secretbox_NONCEBYTES - 1; i >= 0; i--) {
        if (nonce[i] < 255) {
            nonce[i]++;
            break;
        } else
            nonce[i] = 0;
    }
}

static int nonce_compare(const unsigned char *a, const unsigned char *b) {
    for (int i = 0; i < crypto_secretbox_NONCEBYTES; i++) {
        int diff = a[i] - b[i];
        if (diff != 0)
            return diff;
    }
    return 0;
}

static size_t sodiumfn_pubkey_size(void *handle) {
    return crypto_kx_PUBLICKEYBYTES;
}

static const char *sodiumfn_pubkey(void *handle, size_t *len) {
    sodium_t *s = handle;
    *len = sizeof(s->pk);
    return (char *)s->pk;
}

static int sodiumfn_key_exchange(void *handle, const char *key, size_t keylen, const char **message) {
    if (keylen != sodiumfn_pubkey_size(handle)) {
        SET_MESSAGE(message, "Invalid public key size");
        return -1;
    }
    sodium_t *s = handle;
    int res = s->server ? crypto_kx_server_session_keys(s->rx, s->tx, s->pk, s->sk, (unsigned char *)key)
                        : crypto_kx_client_session_keys(s->rx, s->tx, s->pk, s->sk, (unsigned char *)key);
    if (res) {
        SET_MESSAGE(message, "Key exchange failed");
        return -1;
    }
    return keylen;
}

static size_t sodiumfn_encrypt(void *handle, const char *src, size_t srclen, char *dst, size_t dstlen) {
    sodium_t *s = handle;
    size_t nlen = sizeof(s->tx_nonce);
    size_t msglen = srclen + crypto_secretbox_MACBYTES;
    size_t len = nlen + msglen;
    assert(dstlen >= len);

    unsigned char *nonce = (unsigned char *)dst;
    unsigned char *msg = nonce + nlen;
    if (src == dst) {
        memmove(msg, src, srclen);
        src = (char *)msg;
    }

    nonce_increment(s->tx_nonce);
    memcpy(nonce, s->tx_nonce, nlen);
    assert(crypto_secretbox_easy(msg, (unsigned char *)src, srclen, nonce, s->tx) == 0);

    return len;
}

static int sodiumfn_decrypt(void *handle,
                            const char *src,
                            size_t srclen,
                            char *dst,
                            size_t *dstlen,
                            const char **message) {
    sodium_t *s = handle;
    size_t nlen = sizeof(s->rx_nonce);
    size_t msglen = srclen - nlen;
    size_t datalen = msglen - crypto_secretbox_MACBYTES;
    if (srclen < nlen) {
        SET_MESSAGE(message, "Source buffer too small for nonce");
        return -1;
    }
    assert(*dstlen >= datalen);

    const unsigned char *nonce = (unsigned char *)src;
    const unsigned char *msg = nonce + nlen;

    int cmp = nonce_compare(nonce, s->rx_nonce);
    if (cmp <= 0 && abs(cmp) < NONCE_WINDOW_SIZE) {
        SET_MESSAGE(message, "Invalid nonce value");
        return -1;
    }
    memcpy(s->rx_nonce, nonce, nlen);

    if (crypto_secretbox_open_easy((unsigned char *)dst, msg, msglen, s->rx_nonce, s->rx) != 0) {
        SET_MESSAGE(message, "Failed to decrypt message");
        return -1;
    }

    *dstlen = datalen;
    return srclen;
}

static void sodiumfn_deinit(void *handle) {
    assert(handle != NULL);
    sodium_memzero(handle, sizeof(sodium_t));
    sodium_free(handle);
}

int crypto_sodium_init() {
    return sodium_init();
}

void crypto_init_sodium(crypto_t *c, int server) {
    size_t mlen = sizeof(sodium_t);
    sodium_t *s = sodium_malloc(mlen);
    sodium_memzero(s, mlen);
    assert(crypto_kx_keypair(s->pk, s->sk) == 0);
    s->server = server;

    sodium_memzero(c, sizeof(crypto_t));
    c->pubkey_size = sodiumfn_pubkey_size;
    c->pubkey = sodiumfn_pubkey;
    c->key_exchange = sodiumfn_key_exchange;
    c->encrypt = sodiumfn_encrypt;
    c->decrypt = sodiumfn_decrypt;
    c->deinit = sodiumfn_deinit;
    c->handle = s;
}
