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
#include <time.h>

#define APPLICATION_NAME "Ongaku"

#define MAX_CLIENTS 64
#define SOCKET_BUFSIZE 32768
#define STREAM_NAME_MAXLEN 128
#define STREAM_TIMEOUT_SECONDS 30

static pool_t pool;
static socket_t sock = SOCKET_UNDEFINED;
static atomic_bool running = true;
static atomic_bool client_removed = false;

static void on_signal(int sig) {
#ifdef _WIN32
    log_debug("Received signal: %d", sig);
#else
    log_debug("Received signal: %s", strsignal(sig));
#endif
    running = false;
}

typedef struct {
    uint8_t idx;
    atomic_bool removed;
    atomic_bool running;
    int flags;
    socklen_t socklen;
    time_t timer;
    audio_stream_params_t params;
    const uint8_t *ptr;
    struct sockaddr *sa;
    OpusEncoder *enc;
    OpusDecoder *dec;
    audio_stream_t *stream;
    ringbuf_t *rb;
    char addr[64];
    char buf[SOCKET_BUFSIZE];
} client_t;

static client_t *clients[MAX_CLIENTS] = {0};

static audio_callback_result_t on_record(const void *src, size_t srclen, void *userdata) {
    const char *message;
    client_t *c = userdata;
    if (time(NULL) - c->timer > STREAM_TIMEOUT_SECONDS) {
        log_info("%s Client timeout", c->addr);
        return AUDIO_STREAM_COMPLETE;
    }

    char *ptr = c->buf;
    char *tail = c->buf + sizeof(c->buf);
    *ptr++ = PACKET_TYPE_DATA;

    int res = callback_write_record(src, srclen, &c->params, c->enc, ptr, tail - ptr, &message);
    if (res < 0) {
        log_error("%s Failed to write data packet: %s", c->addr, message);
        return AUDIO_STREAM_ABORT;
    }
    ptr += res;

    if (sendto(sock, c->buf, ptr - c->buf, 0, c->sa, c->socklen) < 0) {
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

static void on_error(const char *message, void *userdata) {
    client_t *client = userdata;
    log_error("%s Stream error: %s", client->addr, message);
}

static void on_finished(void *userdata) {
    client_t *c = userdata;
    c->removed = true;
    client_removed = true;
}

static client_t *client_new(const uint8_t *ptr,
                            const struct sockaddr *sa,
                            socklen_t socklen,
                            int flags,
                            const char **message) {
    assert(socklen >= sizeof(struct sockaddr));

    client_t *c = malloc_zero(sizeof(client_t));
    c->idx = *ptr;
    c->ptr = ptr;
    c->flags = flags;
    c->socklen = socklen;

    audio_stream_params_t params = DEFAULT_AUDIO_STREAM_PARAMS(APPLICATION_NAME);
    if (flags & STREAMCFG_FLAG_SAMPLE_F32) {
        params.sample_size = sizeof(float);
        params.sample_format = AUDIO_FORMAT_F32;
    } else {
        params.sample_size = sizeof(opus_int16);
        params.sample_format = AUDIO_FORMAT_S16;
    }
    memcpy(&c->params, &params, sizeof(params));

    if (flags & STREAMCFG_FLAG_CODEC_OPUS) {
        int err;
        c->enc = opus_encoder_create(params.sample_rate, params.channels, OPUS_APPLICATION, &err);
        if (err) {
            SET_MESSAGE(message, opus_strerror(err));
            return NULL;
        }
        c->dec = opus_decoder_create(params.sample_rate, params.channels, &err);
        if (err) {
            SET_MESSAGE(message, opus_strerror(err));
            return NULL;
        }
    }

    c->sa = malloc_copy(sa, socklen);
    c->stream = audio_stream_new(&c->params);
    c->rb =
        ringbuf_new(audio_stream_frame_count(&c->params, FRAME_BUFFER_DURATION), audio_stream_frame_size(&c->params));

    time(&c->timer);
    strsockaddr_r(sa, socklen, c->addr, sizeof(c->addr));

    return c;
}

static int client_start(client_t *c, const char *indev, const char *outdev, const char **message) {
    if (c->running)
        return 0;
    if (audio_stream_connect(c->stream, message))
        goto fail;
    if (c->flags & STREAMCFG_FLAG_INPUT &&
        audio_stream_open_record(c->stream, indev, c->addr, on_record, on_error, on_finished, c, message))
        goto disconnect_fail;
    if (c->flags & STREAMCFG_FLAG_OUTPUT &&
        audio_stream_open_playback(c->stream, outdev, c->addr, on_playback, on_error, on_finished, c, message))
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

static void client_free(client_t *c) {
    if (c->stream)
        audio_stream_free(c->stream);
    if (c->enc)
        opus_encoder_destroy(c->enc);
    if (c->rb)
        ringbuf_free(c->rb);
    if (c->sa)
        free(c->sa);
    free(c);
}

static client_t *add_client(const struct sockaddr *sa, socklen_t socklen, const char *addr, int flags) {
    const char *message;

    uint8_t *ptr = (uint8_t *)pool_get(&pool);
    if (!ptr) {
        log_error("%s Pool exhausted, can't accept anymore client!", addr);
        return NULL;
    }

    client_t *c = client_new(ptr, sa, socklen, flags, &message);
    if (!c) {
        log_error("%s Failed to create client: %s", message);
        return NULL;
    }

    memcpy(c->buf, HANDSHAKE_MAGIC_STRING, HANDSHAKE_MAGIC_STRING_LEN);
    c->buf[HANDSHAKE_MAGIC_STRING_LEN] = c->idx;
    if (sendto(sock, c->buf, HANDSHAKE_MAGIC_STRING_LEN + 1, 0, c->sa, c->socklen) < 0) {
        log_error("%s Failed to send handshake response: %s", c->addr, socket_strerror());
        goto fail;
    }

    if (client_start(c, NULL, NULL, &message)) {
        log_error("%s Failed to start client: %s", c->addr, message);
        goto fail;
    }
    log_info("%s Client started", addr);

    clients[c->idx] = c;
    log_debug("%s Client added, index: %d", addr, c->idx);

    return c;

fail:
    client_free(c);
    pool_put(&pool, ptr);
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

    pool_put(&pool, (void *)c->ptr);
    client_free(c);
}

static void handle_handshake(const struct sockaddr *sa, socklen_t socklen, const char *buf, size_t buflen) {
    const char *addr = strsockaddr(sa, socklen);
    packet_config_t cfg = {.flags = DEFAULT_STREAMCFG_FLAGS};
    const char *ptr = buf;
    const char *tail = buf + buflen;
    ptr += packet_config_read(ptr, tail - ptr, &cfg);
    log_debug("%s flags=%d", addr, cfg.flags);

    client_t *client = add_client(sa, socklen, addr, cfg.flags);
    if (client)
        log_info("%s Handshake success. Client index: %d", addr, client->idx);
}

static void handle_data(client_t *c, const char *buf, size_t buflen) {
    const char *message;
    int res = callback_read_ringbuf(buf, buflen, &c->params, c->dec, c->rb, &message);
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

    log_init();
    if (socket_init(&message)) {
        log_fatal("Failed to initialize socket: %s", message);
        return EXIT_FAILURE;
    }
    if (audio_init(&message)) {
        log_fatal("Failed to initialize audio: %s", message);
        goto fail;
    }

    pool_init(&pool, sizeof(uint8_t), MAX_CLIENTS);
    for (uint8_t idx = 0; idx < MAX_CLIENTS; idx++) {
        uint8_t *ptr = pool_get(&pool);
        *ptr = idx;
        pool_put(&pool, ptr);
    }

    struct sockaddr_in6 sin6;
    struct sockaddr *sa = (struct sockaddr *)&sin6;
    socklen_t socklen = sizeof(sin6);
    sockaddr_ipv4(sa, &socklen, INADDR_ANY, DEFAULT_PORT);
    if ((sock = socket_open(sa->sa_family, &message)) < 0) {
        log_fatal("Failed to create socket: %s", message);
        goto fail;
    }
    optval_t optval = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)))
        log_error("Failed to disable SO_REUSEADDR: %s", socket_strerror());
    if (socket_bind(sock, sa, socklen, &message)) {
        log_fatal("Failed to bind socket: %s", message);
        goto fail;
    }
    log_info("Socket listening at %s", strsockaddr(sa, socklen));

    signal(SIGINT, on_signal);
    socket_set_timeout(sock, 1, &message);

    char buf[SOCKET_BUFSIZE];
    packet_client_header_t hdr;
    while (running) {
        socklen = sizeof(sin6);
        int res = recvfrom(sock, buf, sizeof(buf), 0, sa, &socklen);
        if (res < 0 && !socket_error_timeout()) {
            log_fatal("Failed to receive packet: %s", socket_strerror());
            goto fail;
        }

        handle_client_removal();
        if (res <= 0)
            continue;

        const char *ptr = buf + packet_handshake_check(buf, res);
        const char *tail = buf + res;
        if (ptr != buf) { /* Pointer sliding, this is a handshake packet */
            handle_handshake(sa, socklen, ptr, tail - ptr);
            continue;
        }

        ptr += packet_client_header_read(buf, res, &hdr);
        if (ptr == buf) /* Pointer not sliding indicates failed header read */
            continue;

        client_t *client = clients[hdr.idx];
        if (!client)
            continue;
        time(&client->timer);

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
