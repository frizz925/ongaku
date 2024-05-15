#define _POSIX_C_SOURCE 200809L

#include "callbacks.h"
#include "consts.h"
#include "crypto/crypto.h"
#include "crypto/plaintext.h"
#include "crypto/sodium.h"
#include "ioutil.h"
#include "log.h"
#include "protocol.h"
#include "socket.h"
#include "util.h"

#include <opus/opus.h>

#include <assert.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdnoreturn.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    uint8_t idx;
    time_t timer;
    crypto_t *crypto;
    OpusEncoder *enc;
    OpusDecoder *dec;
    ringbuf_t *rb;
    const audio_stream_params_t *params;
    char buf[SOCKET_BUFSIZE];
} context_t;

static socket_t sock = SOCKET_UNDEFINED;
static atomic_bool running = true;
static char tx_buf[SOCKET_BUFSIZE];

static void on_signal(int sig) {
#ifdef _WIN32
    log_debug("Received signal: %d", sig);
#else
    log_debug("Received signal: %s", strsignal(sig));
#endif
    running = false;
}

static int send_packet(context_t *ctx, uint8_t type, const void *src, size_t srclen, const char **message) {
    char *buf = tx_buf;
    size_t buflen = sizeof(tx_buf);

    packet_client_header_t chdr = {.idx = ctx->idx};
    char *tail = buf + buflen;
    char *base = buf + packet_client_header_write(buf, buflen, &chdr);
    buflen = tail - base;

    packet_header_t hdr = {.type = type};
    char *ptr = base + packet_header_write(base, buflen, &hdr);

    if (src && srclen > 0) {
        assert(tail - ptr >= srclen);
        memcpy(ptr, src, srclen);
        ptr += srclen;
    }
    ptr = base + ioutil_encrypt(ctx->crypto, base, buflen, base, ptr - base);

    int res = send(sock, buf, ptr - buf, 0);
    if (res < 0) {
        SET_MESSAGE(message, socket_strerror());
        return -1;
    }
    return res;
}

static void send_heartbeat(context_t *ctx) {
    const char *message;
    uint32_t timer = htonl(time(NULL));
    if (send_packet(ctx, PACKET_TYPE_HEARTBEAT, &timer, sizeof(timer), &message) < 0)
        log_error("Failed to send heartbeat packet: %s", message);
}

static audio_callback_result_t on_record(const void *src, size_t srclen, void *userdata) {
    const char *message;
    context_t *ctx = userdata;
    if (time(NULL) - ctx->timer > STREAM_TIMEOUT_SECONDS) {
        log_info("Server timeout");
        return AUDIO_STREAM_COMPLETE;
    }
    size_t bufsize = audio_stream_frame_bufsize(ctx->params, ctx->params->frame_duration);

    char *buf = ctx->buf;
    size_t buflen = sizeof(ctx->buf);
    size_t off = 0;
    while (off < srclen) {
        size_t left = srclen - off;
        size_t size = MIN(bufsize, left);
        int res = callback_record_write(src + off, size, ctx->params, ctx->enc, buf, buflen, &message);
        if (res < 0) {
            log_error("Failed to write data packet: %s", message);
            return AUDIO_STREAM_ABORT;
        }
        if (res > 0 && send_packet(ctx, PACKET_TYPE_DATA, buf, res, &message) < 0) {
            log_error("Failed to send audio frame: %s", message);
            return AUDIO_STREAM_ABORT;
        }
        off += size;
    }

    return AUDIO_STREAM_CONTINUE;
}

static audio_callback_result_t on_playback(void *dst, size_t *dstlen, void *userdata) {
    const char *message;
    context_t *ctx = userdata;
    int res = callback_playback_read(dst, dstlen, ctx->rb, &message);
    if (res < 0) {
        log_error("Failed to read audio frames: %s", message);
        return AUDIO_STREAM_ABORT;
    }
    return AUDIO_STREAM_CONTINUE;
}

static void on_error(const char *message, void *userdata) {
    log_error("Stream error: %s", message);
}

static void on_finished(void *userdata) {
    running = false;
}

static void handle_data(context_t *ctx, char *src, size_t srclen) {
    const char *message;
    int res = callback_playback_write(src, srclen, ctx->params, ctx->dec, ctx->rb, &message);
    if (res < -1)
        log_error("Handling data packet error: %s", message);
    else if (res < 0)
        log_warn("Handling data packet warning: %s", message);
}

static int application_loop(int flags,
                            const char *indev,
                            const char *outdev,
                            struct sockaddr *sa,
                            socklen_t socklen,
                            const char *addr,
                            const audio_stream_params_t *params,
                            ringbuf_t *play_rb) {
    int rc = EXIT_SUCCESS;
    int err;
    const char *message;
    audio_stream_t *stream = NULL;
    crypto_t crypto = {0};
    context_t ctx = {
        .rb = play_rb,
        .params = params,
        .crypto = &crypto,
        .enc = NULL,
        .dec = NULL,
    };

    if (flags & STREAMCFG_FLAG_ENCRYPTED)
        crypto_init_sodium(&crypto, 0);
    else
        crypto_init_plaintext(&crypto);

    if (flags & STREAMCFG_FLAG_CODEC_OPUS) {
        ctx.enc = opus_encoder_create(params->sample_rate, params->channels, OPUS_APPLICATION, &err);
        if (err) {
            log_fatal("Failed to create Opus encoder: %s", opus_strerror(err));
            goto fail;
        }
        ctx.dec = opus_decoder_create(params->sample_rate, params->channels, &err);
        if (err) {
            log_fatal("Failed to create Opus decoder: %s", opus_strerror(err));
            goto fail;
        }
    }

    log_info("Connecting to server %s", addr);
    sock = socket_open(sa->sa_family, &message);
    if (sock < 0) {
        log_fatal("Failed to create socket: %s", message);
        goto fail;
    }
    if (socket_set_timeout(sock, 5, &message)) {
        log_fatal("Failed to set socket timeout: %s", message);
        goto fail;
    }
    if (socket_connect(sock, sa, socklen, &message)) {
        log_fatal("Failed to connect to server: %s", message);
        goto fail;
    }

    char buf[SOCKET_BUFSIZE];
    size_t buflen = sizeof(buf);

    char *ptr = buf + packet_handshake_write(buf, buflen);
    char *tail = buf + buflen;

    packet_config_t config = {.flags = flags};
    ptr += packet_config_write(ptr, tail - ptr, &config);

    size_t keylen;
    const char *key = crypto_pubkey(&crypto, &keylen);
    ptr += packet_write(ptr, tail - ptr, key, keylen);

    int handshake_success = 0;
    for (int i = 0; i < HANDSHAKE_RETRY; i++) {
        if (send(sock, buf, ptr - buf, 0) < 0) {
            log_fatal("Failed to send handshake packet: %s", socket_strerror());
            goto fail;
        }
        int res = recv(sock, buf, buflen, 0);
        if (res < 0) {
            if (!socket_error_timeout()) {
                log_fatal("Failed to receive handshake packet: %s", socket_strerror());
                goto fail;
            }
            continue;
        }

        ptr = buf + packet_handshake_check(buf, res);
        tail = buf + res;
        if (ptr == buf) {
            log_error("Invalid handshake packet received");
            continue;
        } else if (ptr == tail) {
            log_error("Missing client index");
            continue;
        }
        ctx.idx = *ptr++;

        if (crypto_key_exchange(&crypto, ptr, keylen, &message) < 0) {
            log_error("Failed to complete key exchange: %s", message);
            continue;
        }

        handshake_success = 1;
        break;
    }
    if (!handshake_success) {
        log_fatal("Failed to complete handshake after %d retries", HANDSHAKE_RETRY);
        goto fail;
    }
    log_info("Handshake packet received. Client index: %d", ctx.idx);
    time(&ctx.timer);

    stream = audio_stream_new(params);
    if (audio_stream_connect(stream, &message)) {
        log_fatal("Failed to connect stream: %s", message);
        goto fail;
    }
    if (flags & STREAMCFG_FLAG_OUTPUT &&
        audio_stream_open_record(stream, indev, addr, on_record, on_error, on_finished, &ctx, &message)) {
        log_fatal("Failed to open record stream: %s", message);
        goto fail;
    }
    if (flags & STREAMCFG_FLAG_INPUT &&
        audio_stream_open_playback(stream, outdev, addr, on_playback, on_error, on_finished, &ctx, &message)) {
        log_fatal("Failed to open playback stream: %s", message);
        goto fail;
    }
    if (audio_stream_start(stream, &message)) {
        log_fatal("Failed to start stream: %s", message);
        goto fail;
    }

    socket_set_timeout(sock, 1, &message);

    time_t timer = time(NULL);
    while (running) {
        if (time(NULL) - timer > HEARTBEAT_INTERVAL_SECONDS) {
            send_heartbeat(&ctx);
            time(&timer);
        }

        int res = recv(sock, buf, buflen, 0);
        if (res < 0 && !socket_error_timeout()) {
            log_fatal("Failed to receive packet: %s", socket_strerror());
            break;
        }
        time((time_t *)&ctx.timer);

        size_t msglen = buflen;
        if (ioutil_decrypt(&crypto, buf, res, buf, &msglen, &message) <= 0)
            continue;

        packet_header_t hdr;
        char *tail = buf + msglen;
        char *ptr = buf + packet_header_read(buf, msglen, &hdr);

        switch (hdr.type) {
        case PACKET_TYPE_DATA:
            handle_data(&ctx, ptr, tail - ptr);
            break;
        case PACKET_TYPE_CLOSE:
            running = false;
            break;
        }
    }

    if (send_packet(&ctx, PACKET_TYPE_CLOSE, NULL, 0, &message) < 0)
        log_error("Failed to send close packet: %s", message);
    goto cleanup;

fail:
    rc = EXIT_FAILURE;

cleanup:
    if (sock >= 0 && socket_close(sock, &message))
        log_error("Failed to close socket: %s", message);
    sock = SOCKET_UNDEFINED;

    if (stream) {
        if (audio_stream_get_state(stream) >= AUDIO_STREAM_RUNNING) {
            if (audio_stream_stop(stream, &message))
                log_error("Failed to stop stream: %s", message);
        }
        if (audio_stream_get_state(stream) >= AUDIO_STREAM_CONNECTED) {
            if (audio_stream_close_playback(stream, &message))
                log_error("Failed to close playback stream: %s", message);
            if (audio_stream_close_record(stream, &message))
                log_error("Failed to close record stream: %s", message);
            if (audio_stream_disconnect(stream, &message))
                log_error("Failed to disconnect stream: %s", message);
        }
        audio_stream_free(stream);
    }

    if (ctx.dec)
        opus_decoder_destroy(ctx.dec);
    if (ctx.enc)
        opus_encoder_destroy(ctx.enc);
    crypto_deinit(&crypto);

    return rc;
}

noreturn static void usage(int rc) {
    fprintf(stderr,
            "Usage: ongaku-client [-hpdiofcs] <server-addr>\n"
            "   -h              print this help\n"
            "   -p port         use different port to connect to the server (default: %d)\n"
            "   -d direction    specifiy direction of the stream: in, out, duplex (default: out)\n"
            "   -i device       use input device name\n"
            "   -o device       use output device name\n"
            "   -f              use 32-bit float sample format\n"
            "   -c              disable Opus codec (see CAUTION)\n"
            "   -s              disable encryption (see WARNING)\n"
            "\n"
            "CAUTION: Disabling Opus codec will result in slightly smaller delay and CPU load\n"
            "but significantly higher network bandwidth.\n"
            "\n"
            "WARNING: Disabling encryption will make your connection susceptible to hijacking\n"
            "or even eavesdropping. Make sure to only disable this in an isolated network.\n",
            DEFAULT_PORT);
    exit(rc);
}

int main(int argc, char *argv[]) {
    int rc = EXIT_SUCCESS;
    const char *message;

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
        goto fail;
    }

    const char *indev = NULL;
    const char *outdev = NULL;
    uint16_t port = DEFAULT_PORT;
    int flags = STREAMCFG_DEFAULT_FLAGS;

    int opt;
    while ((opt = getopt(argc, argv, "hp:d:i:o:fcs")) != -1) {
        switch (opt) {
        case 'h':
            usage(EXIT_SUCCESS);
        case 'p':
            port = atoi(optarg);
            break;
        case 'd':
            if (strncasecmp(optarg, "in", 2) == 0)
                flags |= STREAMCFG_FLAG_INPUT;
            else if (strncasecmp(optarg, "out", 3) == 0)
                flags |= STREAMCFG_FLAG_OUTPUT;
            else if (strncasecmp(optarg, "duplex", 6) == 0)
                flags |= STREAMCFG_FLAG_DUPLEX;
            break;
        case 'i':
            indev = optarg;
            break;
        case 'o':
            outdev = optarg;
            break;
        case 'f':
            flags |= STREAMCFG_FLAG_SAMPLE_F32;
            break;
        case 'c':
            flags &= ~STREAMCFG_FLAG_CODEC_OPUS;
            break;
        case 's':
            flags &= ~STREAMCFG_FLAG_ENCRYPTED;
            break;
        default:
            usage(EXIT_FAILURE);
        }
    }

    if ((flags & STREAMCFG_DIRECTION_MASK) == 0)
        flags |= STREAMCFG_FLAG_OUTPUT;
    log_debug("flags=%d", flags);

    if (optind >= argc)
        usage(EXIT_FAILURE);
    const char *host = argv[optind];

    audio_stream_params_t params = DEFAULT_AUDIO_STREAM_PARAMS(APPLICATION_NAME);
    if (flags & STREAMCFG_FLAG_SAMPLE_F32) {
        params.sample_size = sizeof(float);
        params.sample_format = AUDIO_FORMAT_F32;
    } else {
        params.sample_size = sizeof(opus_int16);
        params.sample_format = AUDIO_FORMAT_S16;
    }

    if (flags & STREAMCFG_FLAG_CODEC_OPUS)
        params.frame_duration = FRAME_OPUS_DURATION;

    struct sockaddr_in6 sin6;
    struct sockaddr *sa = (struct sockaddr *)&sin6;
    socklen_t socklen = sizeof(sin6);
    if (sockaddr_string(sa, &socklen, host, port, &message)) {
        log_fatal("Invalid address %s: %s", argv[1], message);
        goto fail;
    }

    char addrbuf[64];
    const char *addr = strsockaddr_r(sa, socklen, addrbuf, sizeof(addrbuf));

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    size_t fcount = audio_stream_frame_count(&params, FRAME_BUFFER_DURATION);
    size_t fsize = audio_stream_frame_size(&params);

    ringbuf_t *rb = ringbuf_new(fcount, fsize);
    while (running && rc == EXIT_SUCCESS) {
        ringbuf_clear(rb);
        rc = application_loop(flags, indev, outdev, sa, socklen, addr, &params, rb);
    }
    ringbuf_free(rb);

    goto cleanup;

fail:
    rc = EXIT_SUCCESS;

cleanup:
    if (audio_terminate(&message)) {
        log_fatal("Failed to terminate audio: %s", message);
        rc = EXIT_FAILURE;
    }
    if (socket_terminate(&message)) {
        log_fatal("Failed to terminate socket: %s", message);
        rc = EXIT_FAILURE;
    }

    return rc;
}
