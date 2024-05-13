#include "protocol.h"
#include "util.h"

#include <assert.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#endif

size_t packet_write(void *dst, size_t dstlen, const void *src, size_t srclen) {
    assert(dstlen >= srclen);
    return memwrite(dst, src, srclen);
}

size_t packet_read(const void *src, size_t srclen, void *dst, size_t dstlen) {
    return (srclen >= dstlen) ? (dst != src) ? memwrite(dst, src, dstlen) : srclen : 0;
}

size_t packet_data_size_write(char *buf, size_t buflen, size_t size) {
    uint16_t val = htons(size);
    return packet_write(buf, buflen, &val, sizeof(val));
}

size_t packet_data_write(char *dst, size_t dstlen, const char *src, size_t srclen) {
    size_t hdrlen = sizeof(uint16_t);
    size_t res = srclen + hdrlen;
    assert(dstlen >= res);
    char *ptr = dst + hdrlen;
    if (dst == src)
        memmove(ptr, src, srclen);
    else
        memcpy(ptr, src, srclen);
    packet_data_size_write(dst, hdrlen, srclen);
    return res;
}

size_t packet_handshake_write(char *buf, size_t len) {
    return packet_write(buf, len, HANDSHAKE_MAGIC_STRING, HANDSHAKE_MAGIC_STRING_LEN);
}

size_t packet_config_write(char *buf, size_t buflen, const packet_config_t *src) {
    return packet_write(buf, buflen, src, sizeof(packet_config_t));
}

size_t packet_client_header_write(char *buf, size_t buflen, const packet_client_header_t *src) {
    return packet_write(buf, buflen, src, sizeof(packet_client_header_t));
}

size_t packet_header_write(char *buf, size_t buflen, const packet_header_t *src) {
    return packet_write(buf, buflen, src, sizeof(packet_header_t));
}

size_t packet_audio_header_write(char *buf, size_t buflen, uint16_t frames) {
    size_t res = sizeof(uint16_t);
    assert(buflen >= res);
    uint16_t *ptr = (uint16_t *)buf;
    *ptr = htons(frames);
    return res;
}

size_t packet_data_size_read(const char *buf, size_t buflen, size_t *size) {
    uint16_t val;
    size_t res = packet_read(buf, buflen, &val, sizeof(val));
    *size = (res > 0) ? ntohs(val) : 0;
    return res;
}

size_t packet_data_read(const char *src, size_t srclen, char *dst, size_t dstlen) {
    size_t len;
    size_t hdrlen = packet_data_size_read(src, srclen, &len);
    if (hdrlen <= 0 || srclen < hdrlen + len)
        return 0;
    const char *ptr = src + hdrlen;
    if (src == dst)
        memmove(dst, ptr, len);
    else
        memcpy(dst, ptr, len);
    return hdrlen + len;
}

size_t packet_handshake_check(const char *buf, size_t len) {
    size_t res = HANDSHAKE_MAGIC_STRING_LEN;
    if (len < res)
        return 0;
    if (strncmp(buf, HANDSHAKE_MAGIC_STRING, len))
        return 0;
    return res;
}

size_t packet_config_read(const char *buf, size_t buflen, packet_config_t *dst) {
    return packet_read(buf, buflen, dst, sizeof(packet_config_t));
}

size_t packet_client_header_read(const char *buf, size_t buflen, packet_client_header_t *dst) {
    return packet_read(buf, buflen, dst, sizeof(packet_client_header_t));
}

size_t packet_header_read(const char *buf, size_t buflen, packet_header_t *dst) {
    return packet_read(buf, buflen, dst, sizeof(packet_header_t));
}

size_t packet_audio_header_read(const char *buf, size_t buflen, uint16_t *frames) {
    size_t res = sizeof(uint16_t);
    if (buflen < res) {
        *frames = 0;
        return 0;
    }
    uint16_t *ptr = (uint16_t *)buf;
    *frames = ntohs(*ptr);
    return res;
}
