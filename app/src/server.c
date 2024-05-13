#define _POSIX_C_SOURCE 200809L

#include "callbacks.h"
#include "consts.h"
#include "crypto/crypto.h"
#include "crypto/plaintext.h"
#include "crypto/sodium.h"
#include "ioutil.h"
#include "log.h"
#include "pool.h"
#include "protocol.h"
#include "socket.h"
#include "util.h"

#include <opus/opus.h>

#include <assert.h>
#include <signal.h>
#include <stdatomic.h>
#include <time.h>

#define APPLICATION_NAME "Ongaku"

#define MAX_CLIENTS 64
#define SOCKET_BUFSIZE 32768
#define STREAM_NAME_MAXLEN 128
#define STREAM_TIMEOUT_SECONDS 30
#define HEARTBEAT_INTERVAL_SECONDS 10

static pool_t pool;
static socket_t sock = SOCKET_UNDEFINED;
static atomic_bool running = true;
static atomic_bool client_removed = false;
static char tx_buf[SOCKET_BUFSIZE];

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
    crypto_t crypto;
    const uint8_t *iptr;
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

    char *buf = c->buf;
    size_t buflen = sizeof(c->buf);
    packet_header_t hdr = {.type = PACKET_TYPE_DATA};

    char *tail = buf + buflen;
    char *ptr = buf + packet_header_write(buf, buflen, &hdr);

    int res = callback_write_record(src, srclen, &c->params, c->enc, ptr, tail - ptr, &message);
    if (res < 0) {
        log_error("%s Failed to write data packet: %s", c->addr, message);
        return AUDIO_STREAM_ABORT;
    }
    ptr = buf + ioutil_encrypt(&c->crypto, buf, buflen, buf, ptr + res - buf);

    if (sendto(sock, buf, ptr - buf, 0, c->sa, c->socklen) < 0) {
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

static void client_free(client_t *c) {
    if (c->stream)
        audio_stream_free(c->stream);
    if (c->enc)
        opus_encoder_destroy(c->enc);
    if (c->rb)
        ringbuf_free(c->rb);
    if (c->sa)
        free(c->sa);
    crypto_deinit(&c->crypto);
    free(c);
}

static client_t *client_new(const uint8_t *iptr,
                            const struct sockaddr *sa,
                            socklen_t socklen,
                            const char *addr,
                            const char *buf,
                            size_t buflen,
                            const char **message) {
    assert(socklen >= sizeof(struct sockaddr));

    packet_config_t cfg = {.flags = DEFAULT_STREAMCFG_FLAGS};
    const char *ptr = buf + packet_config_read(buf, buflen, &cfg);
    const char *tail = buf + buflen;
    log_debug("%s flags=%d", addr, cfg.flags);

    client_t *c = malloc_zero(sizeof(client_t));
    c->idx = *iptr;
    c->iptr = iptr;
    c->socklen = socklen;
    c->flags = cfg.flags;

    crypto_t *cc = &c->crypto;
    if (c->flags & STREAMCFG_FLAG_ENCRYPTED)
        crypto_init_sodium(cc, 1);
    else
        crypto_init_plaintext(cc);

    size_t keylen = crypto_pubkey_size(cc);
    if (tail - ptr < keylen) {
        *message = "Invalid public key size";
        goto fail;
    }

    int res = crypto_key_exchange(cc, ptr, keylen, message);
    if (res < 0)
        goto fail;

    audio_stream_params_t params = DEFAULT_AUDIO_STREAM_PARAMS(APPLICATION_NAME);
    if (c->flags & STREAMCFG_FLAG_SAMPLE_F32) {
        params.sample_size = sizeof(float);
        params.sample_format = AUDIO_FORMAT_F32;
    } else {
        params.sample_size = sizeof(opus_int16);
        params.sample_format = AUDIO_FORMAT_S16;
    }
    memcpy(&c->params, &params, sizeof(params));

    if (c->flags & STREAMCFG_FLAG_CODEC_OPUS) {
        int err;
        c->enc = opus_encoder_create(params.sample_rate, params.channels, OPUS_APPLICATION, &err);
        if (err) {
            SET_MESSAGE(message, opus_strerror(err));
            goto fail;
        }
        c->dec = opus_decoder_create(params.sample_rate, params.channels, &err);
        if (err) {
            SET_MESSAGE(message, opus_strerror(err));
            goto fail;
        }
        params.in_frame_duration = FRAME_OPUS_DURATION;
    }

    c->sa = malloc_copy(sa, socklen);
    c->stream = audio_stream_new(&c->params);
    c->rb =
        ringbuf_new(audio_stream_frame_count(&c->params, FRAME_BUFFER_DURATION), audio_stream_frame_size(&c->params));
    strncpy(c->addr, addr, sizeof(c->addr));
    time(&c->timer);

    return c;

fail:
    client_free(c);
    return NULL;
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

static client_t *add_client(const struct sockaddr *sa,
                            socklen_t socklen,
                            const char *addr,
                            const char *buf,
                            size_t buflen) {
    const char *message;

    uint8_t *ptr = (uint8_t *)pool_get(&pool);
    if (!ptr) {
        log_error("%s Pool exhausted, can't accept anymore client!", addr);
        return NULL;
    }

    client_t *c = client_new(ptr, sa, socklen, addr, buf, buflen, &message);
    if (!c) {
        log_error("%s Failed to create client: %s", addr, message);
        return NULL;
    }
    clients[c->idx] = c;
    log_debug("%s Client added, index: %d", addr, c->idx);

    return c;
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

    pool_put(&pool, (void *)c->iptr);
    client_free(c);
}

static int send_packet(client_t *c, uint8_t type, const void *src, size_t srclen, const char **message) {
    char *buf = tx_buf;
    size_t buflen = sizeof(tx_buf);

    packet_header_t hdr = {.type = type};
    char *tail = buf + buflen;
    char *ptr = buf + packet_header_write(buf, buflen, &hdr);

    if (src && srclen > 0) {
        assert(tail - ptr >= srclen);
        memcpy(ptr, src, srclen);
        ptr += srclen;
    }
    ptr = buf + ioutil_encrypt(&c->crypto, buf, buflen, buf, ptr - buf);

    if (sendto(sock, buf, ptr - buf, 0, c->sa, c->socklen) < 0) {
        *message = socket_strerror();
        return -1;
    }
    return 0;
}

static void send_heartbeat(client_t *c) {
    const char *message;
    uint32_t timer = htonl(time(NULL));
    if (send_packet(c, PACKET_TYPE_HEARTBEAT, &timer, sizeof(timer), &message) < 0)
        log_error("%s Failed to send heartbeat packet: %s", c->addr, message);
}

static int send_handshake(client_t *c, const char **message) {
    size_t buflen = sizeof(tx_buf);
    char *buf = tx_buf;
    char *ptr = buf + packet_handshake_write(buf, buflen);
    char *tail = buf + buflen;
    *ptr++ = c->idx;

    size_t keylen;
    const char *key = crypto_pubkey(&c->crypto, &keylen);
    ptr += packet_write(ptr, tail - ptr, key, keylen);

    if (sendto(sock, buf, ptr - buf, 0, c->sa, c->socklen) < 0) {
        SET_MESSAGE(message, socket_strerror());
        return -1;
    }

    log_info("%s Handshake success. Client index: %d", c->addr, c->idx);
    return 0;
}

static void handle_handshake(const struct sockaddr *sa, socklen_t socklen, const char *src, size_t srclen) {
    const char *addr = strsockaddr(sa, socklen);
    client_t *client = add_client(sa, socklen, addr, src, srclen);
    if (!client)
        return;

    const char *message;
    if (send_handshake(client, &message)) {
        log_error("%s Failed to send handshake response: %s", addr, message);
        goto fail;
    }
    if (client_start(client, NULL, NULL, &message)) {
        log_error("%s Failed to start client: %s", client->addr, message);
        goto fail;
    }
    log_info("%s Client started", addr);
    return;

fail:
    if (client)
        remove_client(client);
}

static void handle_data(client_t *c, char *src, size_t srclen) {
    const char *message;
    int res = callback_read_ringbuf(src, srclen, &c->params, c->dec, c->rb, &message);
    if (res < -1)
        log_error("%s Handling data packet error: %s", c->addr, message);
    else if (res < 0)
        log_warn("%s Handling data packet warning: %s", c->addr, message);
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

static void handle_client_heartbeat() {
    static time_t timer = 0;
    if (timer == 0)
        time(&timer);
    if (time(NULL) - timer < HEARTBEAT_INTERVAL_SECONDS)
        return;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        client_t *c = clients[i];
        if (!c)
            continue;
        send_heartbeat(c);
    }
}

int main() {
    const char *message;
    int rc = EXIT_SUCCESS;

    log_init();
    if (crypto_sodium_init()) {
        log_fatal("Failed to initialize libsodium");
        return EXIT_FAILURE;
    }
    if (socket_init(&message)) {
        log_fatal("Failed to initialize socket: %s", message);
        return EXIT_FAILURE;
    }
    if (audio_init(&message)) {
        log_fatal("Failed to initialize audio: %s", message);
        goto fail; /* Socket has already been initialized, so we use goto fail */
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
    size_t buflen = sizeof(buf);
    while (running) {
        socklen = sizeof(sin6);
        int res = recvfrom(sock, buf, buflen, 0, sa, &socklen);
        if (res < 0 && !socket_error_timeout()) {
            log_fatal("Failed to receive packet: %s", socket_strerror());
            goto fail;
        }

        handle_client_removal();
        handle_client_heartbeat();
        if (res <= 0)
            continue;

        char *tail = buf + res;
        char *ptr = buf + packet_handshake_check(buf, res);
        if (ptr != buf) { /* Pointer sliding, this is a handshake packet */
            handle_handshake(sa, socklen, ptr, tail - ptr);
            continue;
        }

        packet_client_header_t chdr;
        ptr += packet_client_header_read(buf, res, &chdr);
        if (ptr == buf) /* Pointer not sliding indicates failed header read */
            continue;

        client_t *c = clients[chdr.idx];
        if (!c)
            continue;
        time(&c->timer);

        /* Support for client roaming */
        if (memcmp(c->sa, sa, socklen) != 0)
            memcpy(c->sa, sa, socklen);

        size_t msglen = buf + buflen - ptr;
        if (ioutil_decrypt(&c->crypto, ptr, tail - ptr, ptr, &msglen, &message) <= 0)
            continue;
        tail = ptr + msglen;

        packet_header_t hdr;
        ptr += packet_header_read(ptr, tail - ptr, &hdr);

        switch (hdr.type) {
        case PACKET_TYPE_DATA:
            handle_data(c, ptr, tail - ptr);
            break;
        case PACKET_TYPE_CLOSE:
            remove_client(c);
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
