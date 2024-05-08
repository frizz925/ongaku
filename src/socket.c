#include "socket.h"
#include "util.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/_types/_socklen_t.h>

#ifdef _WIN32

#define ERRMSG_EAFNOSUPPORT "Unsupported socket family"

const char *socket_strerror() {
    static char msg[256];
    msg[0] = '\0';
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL,
                  WSAGetLastError(),
                  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                  msg,
                  sizeof(msg),
                  NULL);
    return msg;
}

int socket_error_timeout() {
    return WSAGetLastError() == WSAETIMEDOUT;
}

int socket_init(const char **message) {
    WORD wVersionRequested = MAKEWORD(2, 2);
    WSADATA wsaData;
    int err = WSAStartup(wVersionRequested, &wsaData);
    if (err) {
        *message = socket_strerror();
        return -1;
    }
    return 0;
}

int socket_close(socket_t sock, const char **message) {
    if (closesocket(sock)) {
        *message = socket_strerror();
        return -1;
    }
    return 0;
}

int socket_terminate(const char **message) {
    int err = WSACleanup();
    if (err) {
        *message = socket_strerror();
        return -1;
    }
    return 0;
}

#else

#include <errno.h>
#include <netdb.h>

#define ERRMSG_EAFNOSUPPORT strerror(EAFNOSUPPORT);

const char *socket_strerror() {
    return strerror(errno);
}

int socket_error_timeout() {
    return errno == EAGAIN || errno == EWOULDBLOCK;
}

int socket_init(const char **message) {
    return 0;
}

int socket_close(socket_t sock, const char **message) {
    if (close(sock)) {
        *message = socket_strerror();
        return -1;
    }
    return 0;
}

int socket_terminate(const char **message) {
    return 0;
}

#endif

socket_t socket_open(int af, const char **message) {
    socket_t sock = socket(af, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0)
        goto error;
    if (af == AF_INET6) {
        optval_t optval = 0;
        setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &optval, sizeof(optval));
    }
    return sock;

error:
    if (sock >= 0)
        close(sock);
    *message = socket_strerror();
    return SOCKET_ERROR;
}

int socket_set_timeout(socket_t sock, double timeout, const char **message) {
#ifdef _WIN32
    DWORD tv = timeout * 1e3;
#else
    struct timeval tv = {
        .tv_sec = timeout,
        .tv_usec = (long)(timeout * 1e6) % 1000000,
    };
#endif
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (optval_t *)&tv, sizeof(tv))) {
        *message = socket_strerror();
        return -1;
    }
    return 0;
}

int socket_bind(socket_t sock, const struct sockaddr *sa, socklen_t socklen, const char **message) {
    if (bind(sock, sa, socklen)) {
        *message = socket_strerror();
        return -1;
    }
    return 0;
}

int socket_connect(socket_t sock, const struct sockaddr *sa, socklen_t socklen, const char **message) {
    if (connect(sock, sa, socklen)) {
        *message = socket_strerror();
        return -1;
    }
    return 0;
}

void sockaddr_ipv4(struct sockaddr *sa, socklen_t *socklen, in_addr_t addr, uint16_t port) {
    assert(*socklen >= sizeof(struct sockaddr_in));
    struct sockaddr_in *sin = (struct sockaddr_in *)sa;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = addr;
    sin->sin_port = htons(port);
    *socklen = sizeof(struct sockaddr_in);
}

void sockaddr_ipv6(struct sockaddr *sa, socklen_t *socklen, struct in6_addr addr, uint16_t port) {
    assert(*socklen >= sizeof(struct sockaddr_in6));
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
    sin6->sin6_family = AF_INET6;
    sin6->sin6_addr = addr;
    sin6->sin6_port = htons(port);
    *socklen = sizeof(struct sockaddr_in6);
}

int sockaddr_string(struct sockaddr *sa, socklen_t *socklen, const char *name, uint16_t port, const char **message) {
    char serv[8];
    struct addrinfo *ai;

    snprintf(serv, sizeof(serv), "%d", port);
    int err = getaddrinfo(name, serv, NULL, &ai);
    if (err) {
        *message = gai_strerror(err);
        return -1;
    }

    assert(*socklen >= ai->ai_addrlen);
    memcpy(sa, ai->ai_addr, ai->ai_addrlen);
    *socklen = ai->ai_addrlen;
    freeaddrinfo(ai);

    return 0;
}

int sockaddr_any(struct sockaddr *sa, socklen_t *socklen, int af, uint16_t port, const char **message) {
    switch (af) {
    case AF_INET:
        sockaddr_ipv4(sa, socklen, INADDR_ANY, port);
        return 0;
    case AF_INET6:
        sockaddr_ipv6(sa, socklen, in6addr_any, port);
        return 0;
    }
    *message = ERRMSG_EAFNOSUPPORT;
    return -1;
}

int sockaddr_loopback(struct sockaddr *sa, socklen_t *socklen, int af, uint16_t port, const char **message) {
    switch (af) {
    case AF_INET:
        sockaddr_ipv4(sa, socklen, htonl(INADDR_LOOPBACK), port);
        return 0;
    case AF_INET6:
        sockaddr_ipv6(sa, socklen, in6addr_loopback, port);
        return 0;
    }
    *message = ERRMSG_EAFNOSUPPORT;
    return -1;
}

const char *strsockaddr(const struct sockaddr *sa, socklen_t socklen) {
    static char buf[128];
    return strsockaddr_r(sa, socklen, buf, sizeof(buf));
}

const char *strsockaddr_r(const struct sockaddr *sa, socklen_t socklen, char *buf, size_t buflen) {
    const char *host;
    const struct sockaddr_in *sin = (struct sockaddr_in *)sa;
    const struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
    uint16_t port;

    switch (sa->sa_family) {
    case AF_INET:
        host = inet_ntop(sa->sa_family, &sin->sin_addr, buf, buflen);
        port = ntohs(sin->sin_port);
        break;
    case AF_INET6:
        host = inet_ntop(sa->sa_family, &sin6->sin6_addr, buf, buflen);
        port = ntohs(sin6->sin6_port);
        break;
    default:
        return NULL;
    }

    size_t hostlen = strlen(host);
    snprintf(buf + hostlen, buflen - hostlen, ":%d", port);
    return buf;
}
