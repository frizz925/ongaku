#include "protocol.h"

size_t packet_handshake_write(char *buf, size_t len) {
    if (len < HANDSHAKE_MAGIC_STRING_LEN)
        return 0;
    memcpy(buf, HANDSHAKE_MAGIC_STRING, HANDSHAKE_MAGIC_STRING_LEN);
    return HANDSHAKE_MAGIC_STRING_LEN;
}

size_t packet_config_write(char *buf, size_t buflen, const packet_config_t *src) {
    size_t cfglen = sizeof(packet_config_t);
    if (buflen < cfglen)
        return 0;
    memcpy(buf, src, cfglen);
    return cfglen;
}

size_t packet_client_header_write(char *buf, size_t buflen, const packet_client_header_t *src) {
    size_t hdrlen = sizeof(packet_client_header_t);
    if (buflen < hdrlen)
        return 0;
    memcpy(buf, src, hdrlen);
    return hdrlen;
}

size_t packet_data_header_write(char *buf, size_t buflen, const packet_data_header_t *src) {
    packet_data_header_t hdr = {
        .size = htons(src->size),
        .frames = htons(src->frames),
    };
    size_t hdrlen = sizeof(hdr);
    if (buflen < hdrlen)
        return 0;
    memcpy(buf, &hdr, hdrlen);
    return hdrlen;
}

size_t packet_handshake_check(const char *buf, size_t len) {
    if (len < HANDSHAKE_MAGIC_STRING_LEN)
        return 0;
    if (strncmp(buf, HANDSHAKE_MAGIC_STRING, HANDSHAKE_MAGIC_STRING_LEN))
        return 0;
    return HANDSHAKE_MAGIC_STRING_LEN;
}

size_t packet_config_read(const char *buf, size_t buflen, packet_config_t *dst) {
    size_t cfglen = sizeof(packet_config_t);
    if (buflen < cfglen)
        return 0;
    memcpy(dst, buf, cfglen);
    return cfglen;
}

size_t packet_client_header_read(const char *buf, size_t buflen, packet_client_header_t *dst) {
    size_t hdrlen = sizeof(packet_client_header_t);
    if (buflen < hdrlen)
        return 0;
    memcpy(dst, buf, hdrlen);
    return hdrlen;
}

size_t packet_data_header_read(const char *buf, size_t buflen, packet_data_header_t *dst) {
    packet_data_header_t hdr;
    size_t hdrlen = sizeof(hdr);
    if (buflen < hdrlen)
        return 0;
    memcpy(&hdr, buf, hdrlen);
    dst->size = ntohs(hdr.size);
    dst->frames = ntohs(hdr.frames);
    return hdrlen;
}
