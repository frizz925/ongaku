#include "callbacks.h"
#include "protocol.h"
#include "util.h"

#include <assert.h>
#include <stdio.h>

int callback_write_record(const void *src,
                          size_t srclen,
                          const audio_stream_params_t *params,
                          OpusEncoder *enc,
                          void *dst,
                          size_t dstlen,
                          const char **message) {
    size_t frame_size = audio_stream_frame_size(params);
    size_t frame_count = srclen / frame_size;

    void *tail = dst + dstlen;
    void *ptr = dst + packet_audio_header_write(dst, dstlen, frame_count);
    size_t buflen = tail - ptr;

    int res;
    if (enc) {
        res = params->sample_format == AUDIO_FORMAT_F32
                  ? opus_encode_float(enc, (float *)src, frame_count, (unsigned char *)ptr, buflen)
                  : opus_encode(enc, (opus_int16 *)src, frame_count, (unsigned char *)ptr, buflen);
        if (res < 0) {
            SET_MESSAGE(message, opus_strerror(res));
            return -1;
        }
    } else {
        assert(buflen >= srclen);
        memcpy(ptr, src, srclen);
        res = srclen;
    }

    return ptr + res - dst;
}

int callback_read_playback(void *dst, size_t *dstlen, ringbuf_t *rb, const char **message) {
    size_t buflen = *dstlen;
    size_t size = ringbuf_size(rb);
    size_t frames = buflen / size;
    if (ringbuf_remaining(rb) < frames) {
        SET_MESSAGE(message, "Ring buffer underflow!");
        memset(dst, 0, frames * size);
        return 1;
    }
    size_t len = ringbuf_read(rb, dst, frames);
    *dstlen = len * size;
    return len;
}

int callback_read_ringbuf(const void *src,
                          size_t srclen,
                          const audio_stream_params_t *params,
                          OpusDecoder *dec,
                          ringbuf_t *rb,
                          const char **message) {
    uint16_t frames_in;
    const char *tail = src + srclen;
    const char *ptr = src + packet_audio_header_read(src, srclen, &frames_in);
    if (frames_in <= 0) {
        SET_MESSAGE(message, "Invalid data header");
        return -1;
    }
    size_t len = tail - ptr;

    /* No Opus decoder, just write directly */
    if (!dec) {
        if (frames_in * audio_stream_frame_size(params) > len) {
            SET_MESSAGE(message, "Invalid frame count");
            return -1;
        }
        if (ringbuf_available(rb) < frames_in) {
            SET_MESSAGE(message, "Ring buffer overflow!");
            return -1;
        }
        ringbuf_write(rb, ptr, frames_in);
        return srclen;
    }

    void *buf;
    size_t frames_out = ringbuf_writeptr(rb, &buf, frames_in);
    if (frames_out < frames_in) {
        SET_MESSAGE(message, "Ring buffer overflow!");
        fprintf(stderr, "frames_in=%d frames_out=%zu\n", frames_in, frames_out);
        return -1;
    }

    int res = params->sample_format == AUDIO_FORMAT_F32
                  ? opus_decode_float(dec, (unsigned char *)ptr, len, (float *)buf, frames_out, 0)
                  : opus_decode(dec, (unsigned char *)ptr, len, (opus_int16 *)buf, frames_out, 0);
    if (res < 0) {
        SET_MESSAGE(message, opus_strerror(res));
        return -1;
    }

    ringbuf_commit_write(rb, res);
    return srclen;
}
