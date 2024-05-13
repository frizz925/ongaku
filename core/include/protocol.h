#ifndef _PROTOCOL_H
#define _PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#define DEFAULT_PORT 7890

#define HANDSHAKE_MAGIC_STRING "iwanttolicksakiabs"
#define HANDSHAKE_MAGIC_STRING_LEN sizeof(HANDSHAKE_MAGIC_STRING)

enum {
    PACKET_TYPE_UNKNOWN,
    PACKET_TYPE_HANDSHAKE,
    PACKET_TYPE_HEARTBEAT,
    PACKET_TYPE_DATA,
    PACKET_TYPE_CLOSE,
};

enum {
    STREAMCFG_FLAG_INPUT = 1,
    STREAMCFG_FLAG_OUTPUT = 1 << 1,
    STREAMCFG_FLAG_CODEC_OPUS = 1 << 2,
    STREAMCFG_FLAG_SAMPLE_F32 = 1 << 3,
    STREAMCFG_FLAG_ENCRYPTED = 1 << 4,
};

#define DEFAULT_STREAMCFG_FLAGS \
    (STREAMCFG_FLAG_INPUT | STREAMCFG_FLAG_OUTPUT | STREAMCFG_FLAG_CODEC_OPUS | STREAMCFG_FLAG_ENCRYPTED)

typedef struct {
    uint8_t flags;
} packet_config_t;

typedef struct {
    uint8_t idx;
} packet_client_header_t;

typedef struct {
    uint8_t type;
} packet_header_t;

size_t packet_write(void *dst, size_t dstlen, const void *src, size_t srclen);
size_t packet_data_size_write(char *buf, size_t buflen, size_t size);
size_t packet_data_write(char *dst, size_t dstlen, const char *src, size_t srclen);
size_t packet_handshake_write(char *buf, size_t len);
size_t packet_config_write(char *buf, size_t buflen, const packet_config_t *src);
size_t packet_client_header_write(char *buf, size_t buflen, const packet_client_header_t *src);
size_t packet_header_write(char *buf, size_t buflen, const packet_header_t *src);
size_t packet_audio_header_write(char *buf, size_t buflen, uint16_t frames);

size_t packet_read(const void *src, size_t srclen, void *dst, size_t dstlen);
size_t packet_data_size_read(const char *buf, size_t buflen, size_t *size);
size_t packet_data_read(const char *src, size_t srclen, char *dst, size_t dstlen);
size_t packet_handshake_check(const char *buf, size_t len);
size_t packet_config_read(const char *buf, size_t buflen, packet_config_t *dst);
size_t packet_client_header_read(const char *buf, size_t buflen, packet_client_header_t *dst);
size_t packet_header_read(const char *buf, size_t buflen, packet_header_t *dst);
size_t packet_audio_header_read(const char *buf, size_t buflen, uint16_t *frames);

#endif
