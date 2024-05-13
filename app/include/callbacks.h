#ifndef _CALLBACKS_H
#define _CALLBACKS_H

#include "audio.h"
#include "ringbuf.h"

#include <opus/opus.h>

int callback_write_record(const void *src,
                          size_t srclen,
                          const audio_stream_params_t *params,
                          OpusEncoder *enc,
                          void *dst,
                          size_t dstlen,
                          const char **message);
int callback_read_playback(void *dst, size_t *dstlen, ringbuf_t *rb, const char **message);
int callback_read_ringbuf(const void *src,
                          size_t srclen,
                          const audio_stream_params_t *params,
                          OpusDecoder *dec,
                          ringbuf_t *rb,
                          const char **message);

#endif
