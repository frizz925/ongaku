#include "callbacks.h"
#include "protocol.h"
#include "util.h"

#include <stdio.h>

int callback_write_record(const void *src,
                          size_t srclen,
                          const audio_stream_params_t *params,
                          OpusEncoder *enc,
                          char *buf,
                          size_t buflen,
                          const char **message) {
    size_t frame_size = audio_stream_frame_size(params);
    size_t frame_count = srclen / frame_size;
    char *tail = buf + buflen;

    packet_data_header_t hdr = {.frames = frame_count};
    size_t hdrlen = sizeof(hdr);
    char *hptr = buf;
    char *ptr = hptr + hdrlen;

    int res;
    buflen = tail - ptr;
    if (enc) {
        res = params->sample_format == AUDIO_FORMAT_F32
                  ? opus_encode_float(enc, (float *)src, frame_count, (unsigned char *)ptr, buflen)
                  : opus_encode(enc, (opus_int16 *)src, frame_count, (unsigned char *)ptr, buflen);
        if (res < 0) {
            SET_MESSAGE(message, opus_strerror(res));
            return -1;
        }
    } else {
        if (buflen < srclen) {
            SET_MESSAGE(message, "Buffer too small!");
            return -1;
        }
        memcpy(ptr, src, srclen);
        res = srclen;
    }
    tail = ptr + res;
    hdr.size = res;

    packet_data_header_write(hptr, ptr - hptr, &hdr);
    return tail - buf;
}

int callback_read_playback(void *dst, size_t *dstlen, ringbuf_t *rb, const char **message) {
    size_t req = *dstlen;
    if (ringbuf_remaining(rb) < req) {
        SET_MESSAGE(message, "Ring buffer underflow!");
        memset(dst, 0, req);
        return 1;
    }
    size_t len = ringbuf_read(rb, dst, req);
    *dstlen = len;
    return len;
}

int callback_read_ringbuf(const char *src,
                          size_t srclen,
                          const audio_stream_params_t *params,
                          OpusDecoder *dec,
                          ringbuf_t *rb,
                          const char **message) {
    void *buf;
    const char *ptr = src;
    const char *tail = src + srclen;

    packet_data_header_t hdr;
    ptr += packet_data_header_read(ptr, tail - ptr, &hdr);
    if (hdr.size <= 0) {
        SET_MESSAGE(message, "Invalid data header");
        return -1;
    } else if (hdr.size > tail - ptr) {
        SET_MESSAGE(message, "Invalid data size");
        return -1;
    }

    if (!dec) /* No Opus decoder, just write directly */
        return ringbuf_write(rb, ptr, hdr.size);

    size_t frame_size = audio_stream_frame_size(params);
    size_t reqlen = hdr.frames * frame_size;
    size_t buflen = ringbuf_writeptr(rb, &buf, reqlen);
    if (buflen < reqlen) {
        SET_MESSAGE(message, "Ring buffer overflow!");
        fprintf(stderr, "reqlen=%zu buflen=%zu\n", reqlen, buflen);
        return -1;
    }

    size_t frame_count = buflen / frame_size;
    int res = params->sample_format == AUDIO_FORMAT_F32
                  ? opus_decode_float(dec, (unsigned char *)ptr, hdr.size, (float *)buf, frame_count, 0)
                  : opus_decode(dec, (unsigned char *)ptr, hdr.size, (opus_int16 *)buf, frame_count, 0);
    if (res < 0) {
        SET_MESSAGE(message, opus_strerror(res));
        return -1;
    }

    size_t len = res * frame_size;
    ringbuf_advance_writeptr(rb, len);
    return len;
}
