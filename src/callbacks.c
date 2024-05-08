#include "callbacks.h"
#include "protocol.h"

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

    packet_data_header_t hdr;
    size_t hdrlen = sizeof(hdr);
    char *hptr = buf;

    char *ptr = hptr + hdrlen;
    int res = opus_encode(enc, (opus_int16 *)src, frame_count, (unsigned char *)ptr, tail - ptr);
    if (res < 0) {
        *message = opus_strerror(res);
        return -1;
    }
    tail = ptr + res;

    hdr.size = res;
    hdr.frames = frame_count;
    packet_data_header_write(hptr, ptr - hptr, &hdr);

    return tail - buf;
}

int callback_read_playback(void *dst, size_t *dstlen, ringbuf_t *rb, const char **message) {
    size_t req = *dstlen;
    if (ringbuf_remaining(rb) < req) {
        *message = "Ring buffer underflow!";
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
        *message = "Invalid data header";
        return -1;
    } else if (hdr.size > tail - ptr) {
        *message = "Invalid data size";
        return -1;
    }

    size_t frame_size = audio_stream_frame_size(params);
    size_t buflen = ringbuf_writeptr(rb, &buf, hdr.frames * frame_size);
    size_t frame_count = buflen / frame_size;
    int res = opus_decode(dec, (unsigned char *)ptr, hdr.size, (opus_int16 *)buf, frame_count, 0);
    if (res < 0) {
        *message = opus_strerror(res);
        return -1;
    }

    size_t len = res * frame_size;
    ringbuf_advance_writeptr(rb, len);
    return len;
}
