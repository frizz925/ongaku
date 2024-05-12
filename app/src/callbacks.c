#include "callbacks.h"
#include "protocol.h"
#include "util.h"

#include <stdio.h>

int callback_write_record(const void *src,
                          size_t srclen,
                          crypto_t *crypto,
                          const audio_stream_params_t *params,
                          OpusEncoder *enc,
                          char *buf,
                          size_t buflen,
                          const char **message) {
    size_t frame_size = audio_stream_frame_size(params);
    size_t frame_count = srclen / frame_size;

    char *base = buf + packet_data_size_write(buf, buflen, 0);
    char *tail = buf + buflen;
    char *ptr = base + packet_audio_header_write(base, tail - base, frame_count);

    int res;
    if (enc) {
        res = params->sample_format == AUDIO_FORMAT_F32
                  ? opus_encode_float(enc, (float *)src, frame_count, (unsigned char *)ptr, tail - ptr)
                  : opus_encode(enc, (opus_int16 *)src, frame_count, (unsigned char *)ptr, tail - ptr);
        if (res < 0) {
            SET_MESSAGE(message, opus_strerror(res));
            return -1;
        }
    } else {
        if (tail - ptr < srclen) {
            SET_MESSAGE(message, "Buffer too small!");
            return -1;
        }
        memcpy(ptr, src, srclen);
        res = srclen;
    }

    size_t size = crypto_encrypt(crypto, base, ptr - base + res, base, tail - base);
    return size + packet_data_size_write(buf, base - buf, size);
}

int callback_read_playback(void *dst, size_t *result, ringbuf_t *rb, const char **message) {
    size_t dstlen = *result;
    size_t size = ringbuf_size(rb);
    size_t frames = dstlen / size;
    if (ringbuf_remaining(rb) < frames) {
        SET_MESSAGE(message, "Ring buffer underflow!");
        memset(dst, 0, frames * size);
        return 1;
    }
    size_t len = ringbuf_read(rb, dst, frames);
    *result = len * size;
    return len;
}

int callback_read_ringbuf(char *src,
                          size_t srclen,
                          size_t buflen,
                          crypto_t *crypto,
                          const audio_stream_params_t *params,
                          OpusDecoder *dec,
                          ringbuf_t *rb,
                          const char **message) {
    size_t size;
    const char *tail = src + srclen;
    const char *ptr = src + packet_data_size_read(src, srclen, &size);
    if (size <= 0 || size > tail - ptr) {
        SET_MESSAGE(message, "Invalid data size");
        return -1;
    }
    buflen = src + buflen - ptr;

    int err;
    char *buf = (char *)ptr;
    ptr += crypto_decrypt(crypto, ptr, size, buf, &buflen, &err, message);
    if (err)
        return -1;
    size_t len = ptr - src;

    uint16_t frames_in;
    ptr = buf + packet_audio_header_read(buf, buflen, &frames_in);
    tail = buf + buflen;
    if (frames_in <= 0) {
        SET_MESSAGE(message, "Invalid data header");
        return -1;
    }

    /* No Opus decoder, just write directly */
    if (!dec) {
        if (frames_in * audio_stream_frame_size(params) > tail - ptr) {
            SET_MESSAGE(message, "Invalid frame count");
            return -1;
        }
        if (ringbuf_available(rb) < frames_in) {
            SET_MESSAGE(message, "Ring buffer overflow!");
            return -1;
        }
        ringbuf_write(rb, ptr, frames_in);
        return len;
    }

    void *rbptr;
    size_t frames_out = ringbuf_writeptr(rb, &rbptr, frames_in);
    if (frames_out < frames_in) {
        SET_MESSAGE(message, "Ring buffer overflow!");
        fprintf(stderr, "frames_in=%d frames_out=%zu\n", frames_in, frames_out);
        return -1;
    }

    int res = params->sample_format == AUDIO_FORMAT_F32
                  ? opus_decode_float(dec, (unsigned char *)ptr, tail - ptr, (float *)rbptr, frames_out, 0)
                  : opus_decode(dec, (unsigned char *)ptr, tail - ptr, (opus_int16 *)rbptr, frames_out, 0);
    if (res < 0) {
        SET_MESSAGE(message, opus_strerror(res));
        return -1;
    }

    ringbuf_commit_write(rb, res);
    return len;
}
