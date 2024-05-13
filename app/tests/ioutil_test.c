#include "crypto/crypto.h"
#include "crypto/plaintext.h"
#include "ioutil.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define SAMPLE_MESSAGE "This is a sample message"

int main() {
    char buf[128];
    const char *message;

    crypto_t crypto;
    crypto_init_plaintext(&crypto);

    size_t msglen = sizeof(SAMPLE_MESSAGE);
    size_t buflen = sizeof(buf);
    size_t enclen = ioutil_encrypt(&crypto, buf, buflen, SAMPLE_MESSAGE, msglen);
    int declen = ioutil_decrypt(&crypto, buf, enclen, buf, &buflen, &message);
    assert(enclen == declen);
    assert(msglen == buflen);
    assert(memcmp(buf, SAMPLE_MESSAGE, msglen) == 0);

    return EXIT_SUCCESS;
}
