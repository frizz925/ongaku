#include "crypto/crypto.h"
#include "util.h"

#include <assert.h>
#include <sodium.h>

#ifdef _WIN32
#else
#include <arpa/inet.h>
#endif

typedef struct {
    unsigned char pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char sk[crypto_kx_PUBLICKEYBYTES];
    unsigned char rx[crypto_kx_SESSIONKEYBYTES];
    unsigned char tx[crypto_kx_SESSIONKEYBYTES];
    unsigned char rx_nonce[crypto_secretbox_NONCEBYTES];
    unsigned char tx_nonce[crypto_secretbox_NONCEBYTES];
    int server;
} sodium_t;

typedef struct {
    uint16_t len;
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
} message_header_t;

static const size_t hdrlen = sizeof(message_header_t);

static void nonce_increment(unsigned char *nonce) {
    for (int i = crypto_secretbox_NONCEBYTES - 1; i > 0; i--) {
        if (nonce[i] < 255) {
            nonce[i]++;
            break;
        }
    }
}

static int nonce_compare(const unsigned char *a, const unsigned char *b) {
    for (int i = 0; i < crypto_secretbox_NONCEBYTES - 1; i++) {
        int diff = a[i] - b[i];
        if (diff != 0)
            return diff;
    }
    return 0;
}

static size_t sodiumfn_write_pubkey(void *handle, char *dst, size_t len) {
    sodium_t *s = handle;
    size_t keylen = sizeof(s->pk);
    assert(len >= keylen);
    return memwrite(dst, s->pk, keylen);
}

static size_t sodiumfn_key_exchange(void *handle, const char *key, size_t keylen, int *err, const char **message) {
    *err = 0;
    if (keylen != crypto_kx_PUBLICKEYBYTES) {
        SET_MESSAGE(message, "Invalid public key size");
        goto fail;
    }
    sodium_t *s = handle;
    int res = s->server ? crypto_kx_server_session_keys(s->rx, s->tx, s->pk, s->sk, (unsigned char *)key)
                        : crypto_kx_client_session_keys(s->rx, s->tx, s->pk, s->sk, (unsigned char *)key);
    if (res) {
        SET_MESSAGE(message, "Key exchange failed");
        goto fail;
    }
    return keylen;

fail:
    *err = -1;
    return 0;
}

static size_t sodiumfn_encrypt(void *handle,
                               const char *src,
                               size_t srclen,
                               char *dst,
                               size_t dstlen,
                               int *err,
                               const char **message) {
    *err = 0;
    size_t msglen = srclen + crypto_secretbox_MACBYTES;
    size_t len = hdrlen + msglen;
    assert(dstlen >= len);

    message_header_t *hdr = (message_header_t *)dst;
    unsigned char *msg = (unsigned char *)(hdr + 1);
    if (src == dst) {
        memmove(msg, src, srclen);
        src = (char *)msg;
    }
    hdr->len = htons(len - hdrlen);

    sodium_t *s = handle;
    memcpy(hdr->nonce, s->tx_nonce, crypto_secretbox_NONCEBYTES);
    nonce_increment(s->tx_nonce);
    assert(crypto_secretbox_easy(msg, (unsigned char *)src, srclen, hdr->nonce, s->tx) == 0);

    return len;
}

static size_t sodiumfn_decrypt(void *handle,
                               const char *src,
                               size_t srclen,
                               char *dst,
                               size_t *dstlen,
                               int *err,
                               const char **message) {
    *err = 0;
    if (srclen < hdrlen) {
        *message = "Source buffer too small for header";
        goto fail;
    }

    const message_header_t *hdr = (message_header_t *)src;
    size_t msglen = ntohs(hdr->len);
    size_t len = hdrlen + msglen;
    if (srclen < len) {
        *message = "Source buffer too small for message";
        goto fail;
    }
    size_t datalen = len - crypto_secretbox_MACBYTES;
    assert(*dstlen >= datalen);

    sodium_t *s = handle;
    if (nonce_compare(hdr->nonce, s->rx_nonce) <= 0) {
        *message = "Invalid nonce value";
        goto fail;
    }
    memcpy(s->rx_nonce, hdr->nonce, crypto_secretbox_NONCEBYTES);

    const unsigned char *msg = (unsigned char *)(hdr + 1);
    if (src == dst) {
        memmove(dst, msg, msglen);
        msg = (unsigned char *)dst;
    }
    if (crypto_secretbox_open_easy((unsigned char *)dst, msg, msglen, s->rx_nonce, s->rx) != 0) {
        *message = "Failed to decrypt message";
        goto fail;
    }

    *dstlen = datalen;
    return len;

fail:
    *err = -1;
    return 0;
}

static void sodiumfn_deinit(void *handle) {
    assert(handle != NULL);
    sodium_memzero(handle, sizeof(sodium_t));
    sodium_free(handle);
}

int crypto_sodium_init(const char **message) {
    if (sodium_init() < 0) {
        *message = "Failed to initialize libsodium";
        return -1;
    }
    return 0;
}

int crypto_sodium_terminate(const char **message) {
    return 0;
}

void crypto_init_sodium(crypto_t *c, int server) {
    size_t mlen = sizeof(sodium_t);
    sodium_t *s = sodium_malloc(mlen);
    sodium_memzero(s, mlen);
    assert(crypto_kx_keypair(s->pk, s->sk) == 0);
    s->server = server;

    c->write_pubkey = sodiumfn_write_pubkey;
    c->key_exchange = sodiumfn_key_exchange;
    c->encrypt = sodiumfn_encrypt;
    c->decrypt = sodiumfn_decrypt;
    c->deinit = sodiumfn_deinit;
    c->handle = s;
}
