#ifndef _IOUTIL_H
#define _IOUTIL_H

#include "crypto/crypto.h"

size_t ioutil_encrypt(crypto_t *crypto, char *dst, size_t dstlen, const char *src, size_t srclen);
int ioutil_decrypt(crypto_t *crypto, const char *src, size_t srclen, char *dst, size_t *dstlen, const char **message);

#endif
