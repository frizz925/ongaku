#include "callbacks.h"
#include "log.h"
#include "pool.h"
#include "protocol.h"
#include "util.h"

#include <opus/opus.h>

#include <assert.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define APPLICATION_NAME "Ongaku"

#define MAX_CLIENTS 64
#define RINGBUF_SIZE 65536
#define SOCKET_BUFSIZE 32768
#define STREAM_BUFSIZE 65536
#define STREAM_NAME_MAXLEN 128
#define STREAM_TIMEOUT_SECONDS 30

static pool_t pool;
static socket_t sock = SOCKET_UNDEFINED;
static atomic_bool running = false;
static atomic_bool client_removed = false;
static const audio_stream_params_t params = DEFAULT_AUDIO_STREAM_PARAMS(APPLICATION_NAME);

static void on_signal(int sig) {
#ifdef _WIN32
    log_debug("Received signal: %d", sig);
#else
    log_debug("Received signal: %s", strsignal(sig));
#endif
    running = false;
    socket_self_signal(sock);
}

typedef struct {
    uint8_t idx;
    bool assigned;
    atomic_bool removed;
    atomic_bool running;
    socklen_t socklen;
    atomic_ulong timer;
    struct sockaddr *sa;
    OpusEncoder *enc;
    OpusDecoder *dec;
    audio_stream_t *stream;
    ringbuf_t *rb;
    char addr[64];
    char buf[STREAM_BUFSIZE];
    char sendbuf[SOCKET_BUFSIZE];
    char ringbuf[RINGBUF_SIZE];
} client_t;

static client_t *clients[MAX_CLIENTS] = {0};

static audio_callback_result_t on_error(const char *message, void *userdata) {
    client_t *client = userdata;
    log_error("%s Stream error: %s", client->addr, message);
    return AUDIO_STREAM_ABORT;
}

static audio_callback_result_t on_record(const void *src, size_t srclen, void *userdata) {
    const char *message;
    client_t *c = userdata;
    if ((uint64_t)time(NULL) - c->timer > STREAM_TIMEOUT_SECONDS) {
        log_info("%s Client timeout", c->addr);
        c->removed = true;
        client_removed = true;
        socket_self_signal(sock);
        return AUDIO_STREAM_COMPLETE;
    }

    char *ptr = c->sendbuf;
    char *tail = c->sendbuf + sizeof(c->sendbuf);
    *ptr++ = PACKET_TYPE_DATA;

    int res = callback_write_record(src, srclen, &params, c->enc, ptr, tail - ptr, &message);
    if (res < 0) {
        log_error("%s Failed to write data packet: %s", c->addr, message);
        return AUDIO_STREAM_ABORT;
    }
    ptr += res;

    if (sendto(sock, c->sendbuf, ptr - c->sendbuf, 0, c->sa, c->socklen) < 0) {
        log_error("%s Failed to send audio frame: %s", c->addr, socket_strerror());
        return AUDIO_STREAM_ABORT;
    }
    return AUDIO_STREAM_CONTINUE;
}

static audio_callback_result_t on_playback(void *dst, size_t *dstlen, void *userdata) {
    const char *message;
    client_t *c = userdata;
    int res = callback_read_playback(dst, dstlen, c->rb, &message);
    if (res < 0) {
        log_error("%s Failed to read audio frames: %s", c->addr, message);
        return AUDIO_STREAM_ABORT;
    }
    return AUDIO_STREAM_CONTINUE;
}

static int client_init(client_t *c,
                       const audio_stream_params_t *params,
                       const struct sockaddr *sa,
                       socklen_t socklen,
                       const char **message) {
    int err;
    c->enc = opus_encoder_create(params->sample_rate, params->channels, OPUS_APPLICATION_RESTRICTED_LOWDELAY, &err);
    if (err) {
        *message = opus_strerror(err);
        return -1;
    }
    c->dec = opus_decoder_create(params->sample_rate, params->channels, &err);
    if (err) {
        *message = opus_strerror(err);
        return -1;
    }

    c->socklen = socklen;
    c->sa = malloc_copy(sa, socklen);
    c->stream = audio_stream_new(params);
    c->rb = ringbuf_init(c->ringbuf, sizeof(c->ringbuf));

    time((time_t *)&c->timer);
    strsockaddr_r(sa, socklen, c->addr, sizeof(c->addr));

    assert(c->socklen >= sizeof(struct sockaddr));

    return 0;
}

static int client_start(client_t *c, const char *indev, const char *outdev, const char **message) {
    if (c->running)
        return 0;
    if (audio_stream_connect(c->stream, message))
        goto fail;
    if (audio_stream_open_record(c->stream, indev, c->addr, on_record, on_error, c, message))
        goto disconnect_fail;
    if (audio_stream_open_playback(c->stream, outdev, c->addr, on_playback, on_error, c, message))
        goto disconnect_fail;
    if (audio_stream_start(c->stream, message))
        goto disconnect_fail;
    c->running = true;
    return 0;

disconnect_fail:
    audio_stream_close_playback(c->stream, message);
    audio_stream_close_record(c->stream, message);
    audio_stream_disconnect(c->stream, message);

fail:
    audio_stream_deinit(c->stream);
    return -1;
}

static int client_stop(client_t *c, const char **message) {
    if (!c->running)
        return 0;
    if (audio_stream_stop(c->stream, message))
        return -1;
    if (audio_stream_close_playback(c->stream, message))
        return -1;
    if (audio_stream_close_record(c->stream, message))
        return -1;
    if (audio_stream_disconnect(c->stream, message))
        return -1;
    c->running = false;
    return 0;
}

static void client_deinit(client_t *c) {
    if (c->stream)
        audio_stream_free(c->stream);
    if (c->enc)
        opus_encoder_destroy(c->enc);
    if (c->sa)
        free(c->sa);

    c->removed = false;
    c->running = false;
    c->socklen = 0;
    c->timer = 0;
    c->sa = NULL;
    c->enc = NULL;
    c->stream = NULL;
    c->rb = NULL;
    c->addr[0] = '\0';
}

static client_t *add_client(const struct sockaddr *sa, socklen_t socklen, const char *addr) {
    static uint8_t client_idx = 0;
    const char *message;

    client_t *c = (client_t *)pool_get(&pool);
    if (!c) {
        log_error("%s Pool exhausted, can't accept anymore client!", addr);
        return NULL;
    }
    if (!c->assigned) {
        if (client_idx >= MAX_CLIENTS) {
            log_error("%s Maximum clients reached!", addr);
            goto fail;
        }
        c->idx = client_idx++;
        c->assigned = true;
    }

    if (client_init(c, &params, sa, socklen, &message)) {
        log_error("%s Failed to initialize client: %s", message);
        goto fail;
    }

    memcpy(c->sendbuf, HANDSHAKE_MAGIC_STRING, HANDSHAKE_MAGIC_STRING_LEN);
    c->sendbuf[HANDSHAKE_MAGIC_STRING_LEN] = c->idx;
    if (sendto(sock, c->sendbuf, HANDSHAKE_MAGIC_STRING_LEN + 1, 0, c->sa, c->socklen) < 0) {
        log_error("%s Failed to send handshake response: %s", c->addr, socket_strerror());
        goto fail;
    }

    if (client_start(c, NULL, NULL, &message)) {
        log_error("%s Failed to start client: %s", c->addr, message);
        goto fail;
    }
    log_info("%s Client started", addr);

    clients[c->idx] = c;
    log_debug("%s Client added, index: %d", c->addr, c->idx);

    return c;

fail:
    client_deinit(c);
    pool_put(&pool, c);
    return NULL;
}

static void remove_client(client_t *c) {
    const char *message;
    if (c->running) {
        if (client_stop(c, &message))
            log_error("%s Failed to stop client: %s", c->addr, message);
        else
            log_info("%s Client stopped", c->addr);
    }
    clients[c->idx] = NULL;
    log_debug("%s Client removed, index: %d", c->addr, c->idx);

    uint8_t flag = PACKET_TYPE_CLOSE;
    if (sendto(sock, (char *)&flag, sizeof(flag), 0, c->sa, c->socklen) < 0)
        log_error("%s Failed to send close packet: %s", c->addr, socket_strerror());

    client_deinit(c);
    pool_put(&pool, c);
}

static void handle_handshake(const struct sockaddr *sa, socklen_t socklen) {
    const char *addr = strsockaddr(sa, socklen);
    client_t *client = add_client(sa, socklen, addr);
    if (client)
        log_info("%s Handshake success. Client index: %d", addr, client->idx);
}

static void handle_data(client_t *c, const char *buf, size_t buflen) {
    const char *message;
    int res = callback_read_ringbuf(buf, buflen, c->buf, sizeof(c->buf), &params, c->dec, c->rb, &message);
    if (res < 0)
        log_error("%s Handling data packet error: %s", c->addr, message);
}

static void handle_client_removal() {
    if (!client_removed)
        return;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        client_t *c = clients[i];
        if (!c || !c->removed)
            continue;
        remove_client(c);
    }
    client_removed = false;
}

int main() {
    const char *message;
    int rc = EXIT_SUCCESS;

    if (socket_init(&message)) {
        log_fatal("Failed to initialize socket: %s", message);
        return EXIT_FAILURE;
    }
    if (audio_init(&message)) {
        log_fatal("Failed to initialize audio: %s", message);
        goto fail;
    }
    pool_init(&pool, sizeof(client_t), 0);

    struct sockaddr_in6 sin6;
    struct sockaddr *sa = (struct sockaddr *)&sin6;
    socklen_t socklen = sizeof(sin6);
    sockaddr_ipv4(sa, socklen, INADDR_ANY, DEFAULT_PORT);
    if ((sock = socket_open(sa->sa_family, &message)) < 0) {
        log_fatal("Failed to create socket: %s", message);
        goto fail;
    }
    optval_t optval = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)))
        log_error("Failed to disable SO_REUSEADDR: %s", socket_strerror());
    if (bind(sock, sa, socklen)) {
        log_fatal("Failed to bind socket: %s", socket_strerror());
        goto fail;
    }
    log_info("Socket listening at %s", strsockaddr(sa, socklen));

    running = true;
    signal(SIGINT, on_signal);

    char buf[SOCKET_BUFSIZE];
    packet_client_header_t hdr;
    while (running) {
        socklen = sizeof(sin6);
        int res = recvfrom(sock, buf, sizeof(buf), 0, sa, &socklen);
        if (res < 0) {
            log_fatal("Failed to receive packet: %s", socket_strerror());
            goto fail;
        }

        handle_client_removal();
        if (res <= 0)
            continue;

        if (packet_handshake_check(buf, res)) {
            handle_handshake(sa, socklen);
            continue;
        }

        const char *ptr = buf;
        const char *tail = buf + res;
        ptr += packet_client_header_read(buf, res, &hdr);
        if (ptr == buf) /* Pointer not moving indicates failed header read */
            continue;

        client_t *client = clients[hdr.idx];
        if (!client)
            continue;
        time((time_t *)&client->timer);

        switch (hdr.type) {
        case PACKET_TYPE_DATA:
            handle_data(client, ptr, tail - ptr);
            break;
        case PACKET_TYPE_CLOSE:
            remove_client(client);
            break;
        }
    }

    goto cleanup;

fail:
    rc = EXIT_FAILURE;

cleanup:
    for (int i = 0; i < MAX_CLIENTS; i++) {
        client_t *client = clients[i];
        if (client)
            remove_client(client);
    }
    if (sock != SOCKET_UNDEFINED) {
        if (socket_close(sock, &message)) {
            log_error("Failed to close socket: %s", message);
            rc = EXIT_FAILURE;
        } else
            log_info("Socket closed");
    }
    if (audio_terminate(&message)) {
        log_error("Failed to terminate audio: %s", message);
        rc = EXIT_FAILURE;
    }
    if (socket_terminate(&message)) {
        log_error("Failed to terminate socket: %s", message);
        rc = EXIT_FAILURE;
    }
    pool_deinit(&pool);
    return rc;
}
