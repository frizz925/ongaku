#include "crypto/crypto.h"
#include "crypto/plaintext.h"
#include "crypto/sodium.h"

#include <sodium.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define SAMPLE_MESSAGE "This is a plaintext message"
#define MESSAGING_LOOP 300

static void test_suite(crypto_t *c, crypto_t *s) {
    int err;
    char msg[128] = SAMPLE_MESSAGE;
    size_t msglen = sizeof(SAMPLE_MESSAGE);

    size_t spklen;
    const char *spk = crypto_pubkey(s, &spklen);
    crypto_key_exchange(c, spk, spklen, &err, NULL);
    assert(err == 0);

    size_t cpklen;
    const char *cpk = crypto_pubkey(c, &cpklen);
    crypto_key_exchange(s, cpk, cpklen, &err, NULL);
    assert(err == 0);

    for (int i = 0; i < MESSAGING_LOOP; i++) {
        size_t enclen = crypto_encrypt(c, msg, sizeof(SAMPLE_MESSAGE), msg, sizeof(msg));
        assert(err == 0);
        assert(enclen >= msglen);

        msglen = sizeof(msg);
        size_t declen = crypto_decrypt(s, msg, enclen, msg, &msglen, &err, NULL);
        assert(err == 0);
        assert(enclen == declen);

        assert(memcmp(msg, SAMPLE_MESSAGE, msglen) == 0);
    }

    crypto_deinit(s);
    crypto_deinit(c);
}

static void none_test() {
    crypto_t c = {0};

    size_t pklen;
    const char *pk = crypto_pubkey(&c, &pklen);
    assert(pk == NULL);
    assert(pklen == 0);

    int err;
    const char *errmsg;
    assert(crypto_key_exchange(&c, pk, pklen, &err, &errmsg) == 0);
    assert(err != 0);

    char msg[] = SAMPLE_MESSAGE;
    size_t msglen = sizeof(msg);
    assert(crypto_encrypt(&c, msg, msglen, msg, msglen) == 0);
    assert(crypto_decrypt(&c, msg, msglen, msg, &msglen, &err, &errmsg) == 0);
    assert(err != 0);

    crypto_deinit(&c);
}

static void plaintext_test() {
    crypto_t c;
    crypto_init_plaintext(&c);
    test_suite(&c, &c);
}

static void sodium_test() {
    unsigned char pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char sk[crypto_kx_SECRETKEYBYTES];

    assert(crypto_sodium_init() == 0);
    assert(crypto_kx_keypair(pk, sk) == 0);

    crypto_t c, s;
    crypto_init_sodium(&c, 0);
    crypto_init_sodium(&s, 1);
    test_suite(&c, &s);
}

int main() {
    none_test();
    plaintext_test();
    sodium_test();
    return EXIT_SUCCESS;
}
