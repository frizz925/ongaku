#ifndef _CRYPTO_SODIUM_H
#define _CRYPTO_SODIUM_H

#include "crypto.h"

int crypto_sodium_init();
void crypto_init_sodium(crypto_t *crypto, int server);

#endif
