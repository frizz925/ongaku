#ifndef _PROTOCOL_H
#define _PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#else
#include <netinet/in.h>
#endif

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

typedef struct {
    uint8_t flags;
} packet_config_t;

typedef struct {
    uint8_t type;
} packet_server_header_t;

typedef struct {
    uint8_t idx;
    uint8_t type;
} packet_client_header_t;

typedef struct {
    uint16_t size;
    uint16_t frames;
} packet_data_header_t;

size_t packet_handshake_write(char *buf, size_t len);
size_t packet_config_write(char *buf, size_t buflen, const packet_config_t *src);
size_t packet_server_header_write(char *buf, size_t buflen, const packet_server_header_t *src);
size_t packet_client_header_write(char *buf, size_t buflen, const packet_client_header_t *src);
size_t packet_data_header_write(char *buf, size_t buflen, const packet_data_header_t *src);

size_t packet_handshake_check(const char *buf, size_t len);
size_t packet_config_read(const char *buf, size_t buflen, packet_config_t *dst);
size_t packet_server_header_read(const char *buf, size_t buflen, packet_server_header_t *dst);
size_t packet_client_header_read(const char *buf, size_t buflen, packet_client_header_t *dst);
size_t packet_data_header_read(const char *buf, size_t buflen, packet_data_header_t *dst);

#endif
