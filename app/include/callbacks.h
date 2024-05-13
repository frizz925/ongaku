#ifndef _CALLBACKS_H
#define _CALLBACKS_H

#include "audio.h"
#include "crypto/crypto.h"
#include "ringbuf.h"

#include <opus/opus.h>

int callback_write_record(const void *src,
                          size_t srclen,
                          crypto_t *crypto,
                          const audio_stream_params_t *params,
                          OpusEncoder *enc,
                          char *buf,
                          size_t buflen,
                          const char **message);
int callback_read_playback(void *dst, size_t *dstlen, ringbuf_t *rb, const char **message);
int callback_read_ringbuf(char *buf,
                          size_t srclen,
                          size_t buflen,
                          crypto_t *crypto,
                          const audio_stream_params_t *params,
                          OpusDecoder *dec,
                          ringbuf_t *rb,
                          const char **message);

#endif