#include "callbacks.h"
#include "protocol.h"
#include "util.h"

int callback_record_write(const void *src,
                          size_t srclen,
                          const audio_stream_params_t *params,
                          OpusEncoder *enc,
                          void *dst,
                          size_t dstlen,
                          const char **message) {
    size_t fsize = audio_stream_frame_size(params);
    size_t fcount = srclen / fsize;

    void *tail = dst + dstlen;
    void *ptr = dst + packet_audio_header_write(dst, dstlen, fcount);
    size_t buflen = tail - ptr;

    int res;
    if (enc) {
        res = params->sample_format == AUDIO_FORMAT_F32
                  ? opus_encode_float(enc, (float *)src, fcount, (unsigned char *)ptr, buflen)
                  : opus_encode(enc, (opus_int16 *)src, fcount, (unsigned char *)ptr, buflen);
        if (res < 0) {
            SET_MESSAGE(message, opus_strerror(res));
            return -1;
        }
    } else {
        if (dstlen < srclen) {
            SET_MESSAGE(message, "Destination buffer too small!");
            return -1;
        }
        memcpy(ptr, src, srclen);
        res = srclen;
    }

    return ptr + res - dst;
}

int callback_playback_read(void *dst, size_t *dstlen, ringbuf_t *rb, const char **message) {
    size_t buflen = *dstlen;
    size_t size = ringbuf_size(rb);
    size_t frames = ringbuf_remaining(rb);
    size_t req_frames = buflen / size;
    if (frames < req_frames) {
        memset(dst, 0, buflen);
        return buflen;
    }
    size_t len = ringbuf_read(rb, dst, req_frames) * size;
    *dstlen = len;
    return len;
}

int callback_playback_write(const void *src,
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
        return -2;
    }
    size_t len = tail - ptr;

    /* No Opus decoder, just write directly */
    if (!dec) {
        if (frames_in * audio_stream_frame_size(params) > len) {
            SET_MESSAGE(message, "Invalid frame count");
            return -2;
        }
        size_t frames_out = ringbuf_available(rb);
        if (frames_out < frames_in) {
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
