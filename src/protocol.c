#include "protocol.h"
#include "log.h"
#include "socket.h"

void socket_self_signal(socket_t listener) {
    const char *errmsg;
    socket_t sock = SOCKET_UNDEFINED;

    struct sockaddr_in6 sin6;
    struct sockaddr *sa = (struct sockaddr *)&sin6;
    socklen_t socklen = sizeof(sin6);
    if (getsockname(listener, sa, &socklen)) {
        log_fatal("Failed to get listener socket address: %s", socket_strerror());
        goto cleanup;
    }
    if ((sock = socket_open(sa->sa_family, &errmsg)) < 0) {
        log_fatal("Failed to create socket for signal: %s", errmsg);
        goto cleanup;
    }

    char buf[64];
    switch (sa->sa_family) {
    case AF_INET:
        ((struct sockaddr_in *)sa)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        break;
    case AF_INET6:
        ((struct sockaddr_in6 *)sa)->sin6_addr = in6addr_loopback;
        break;
    default:
        log_error("Unsupported socket family: %d", sa->sa_family);
        goto cleanup;
    }
    log_debug("sockaddr=%s", strsockaddr_r(sa, socklen, buf, sizeof(buf)));

    int send = sendto(sock, "", 0, 0, sa, socklen);
    if (send < 0)
        log_fatal("Failed to send packet for signal: %s", socket_strerror());

cleanup:
    if (sock >= 0)
        close(sock);
}

size_t packet_handshake_write(char *buf, size_t len) {
    if (len < HANDSHAKE_MAGIC_STRING_LEN)
        return 0;
    memcpy(buf, HANDSHAKE_MAGIC_STRING, HANDSHAKE_MAGIC_STRING_LEN);
    return HANDSHAKE_MAGIC_STRING_LEN;
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
