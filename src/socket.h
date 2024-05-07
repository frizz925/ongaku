#ifndef _SOCKET_H
#define _SOCKET_H

#define SOCKET_UNDEFINED -1
#define SOCKET_ERROR SOCKET_UNDEFINED

#if _WIN32

#include <io.h>
#include <stdint.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

typedef SOCKET socket_t;
typedef int socklen_t;
typedef u_long in_addr_t;
typedef char optval_t;

#else

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

typedef int socket_t;
typedef int optval_t;

#endif

const char *socket_strerror();

int socket_init(const char **message);
socket_t socket_open(int af, const char **message);
int socket_close(socket_t sock, const char **message);
int socket_terminate(const char **message);

void sockaddr_ipv4(struct sockaddr *sa, size_t socklen, in_addr_t addr, uint16_t port);
void sockaddr_ipv6(struct sockaddr *sa, size_t socklen, struct in6_addr addr, uint16_t port);
int sockaddr_string(struct sockaddr *sa, size_t socklen, const char *name, uint16_t port, const char **message);
int sockaddr_any(struct sockaddr *sa, size_t socklen, int af, uint16_t port, const char **message);
int sockaddr_loopback(struct sockaddr *sa, size_t socklen, int af, uint16_t port, const char **message);

const char *strsockaddr(const struct sockaddr *sa, socklen_t socklen);
const char *strsockaddr_r(const struct sockaddr *sa, socklen_t socklen, char *buf, size_t buflen);

#endif
