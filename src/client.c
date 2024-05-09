#include "callbacks.h"
#include "log.h"
#include "protocol.h"

#include <opus/opus.h>

#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <time.h>
#include <unistd.h>

#define APPLICATION_NAME "Ongaku"
#define SOCKET_BUFSIZE 32768
#define STREAM_TIMEOUT_SECONDS 30
#define HEARTBEAT_INTERVAL_SECONDS 15
#define HANDSHAKE_RETRY 5

typedef struct {
    uint8_t idx;
    time_t timer;
    OpusEncoder *enc;
    OpusDecoder *dec;
    ringbuf_t *rb;
    const audio_stream_params_t *params;
    char buf[SOCKET_BUFSIZE];
} context_t;

static socket_t sock = SOCKET_UNDEFINED;
static atomic_bool running = true;

static void on_signal(int sig) {
#ifdef _WIN32
    log_debug("Received signal: %d", sig);
#else
    log_debug("Received signal: %s", strsignal(sig));
#endif
    running = false;
}

static void send_heartbeat(socket_t sock, uint8_t idx) {
    packet_client_header_t hdr = {.idx = idx, .type = PACKET_TYPE_HEARTBEAT};
    if (send(sock, (char *)&hdr, sizeof(hdr), 0) < 0)
        log_error("Failed to send heartbeat packet: %s", socket_strerror());
}

static audio_callback_result_t on_record(const void *src, size_t srclen, void *userdata) {
    const char *message;
    context_t *ctx = userdata;
    if (time(NULL) - ctx->timer > STREAM_TIMEOUT_SECONDS) {
        return AUDIO_STREAM_COMPLETE;
    }

    char *ptr = ctx->buf;
    char *tail = ctx->buf + sizeof(ctx->buf);
    packet_client_header_t hdr = {.idx = ctx->idx, .type = PACKET_TYPE_DATA};
    ptr += packet_client_header_write(ptr, tail - ptr, &hdr);

    int res = callback_write_record(src, srclen, ctx->params, ctx->enc, ptr, tail - ptr, &message);
    if (res < 0) {
        log_error("Failed to write data packet: %s", message);
        return AUDIO_STREAM_ABORT;
    }
    ptr += res;

    if (send(sock, ctx->buf, ptr - ctx->buf, 0) < 0) {
        log_error("Failed to send audio frame: %s", socket_strerror());
        return AUDIO_STREAM_ABORT;
    }
    return AUDIO_STREAM_CONTINUE;
}

static audio_callback_result_t on_playback(void *dst, size_t *dstlen, void *userdata) {
    const char *message;
    context_t *ctx = userdata;
    int res = callback_read_playback(dst, dstlen, ctx->rb, &message);
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

static void handle_data(context_t *ctx, const void *buf, size_t buflen) {
    const char *message;
    int res = callback_read_ringbuf(buf, buflen, ctx->params, ctx->dec, ctx->rb, &message);
    if (res < 0)
        log_error("Handling data packet error: %s", message);
}

static int application_loop(int flags,
                            const char *indev,
                            const char *outdev,
                            struct sockaddr *sa,
                            socklen_t socklen,
                            const char *addr,
                            const audio_stream_params_t *params,
                            ringbuf_t *rb) {
    int rc = EXIT_SUCCESS;
    const char *message;
    audio_stream_t *stream = NULL;
    context_t ctx = {
        .rb = rb,
        .params = params,
        .enc = NULL,
        .dec = NULL,
    };

    if (flags & STREAMCFG_FLAG_CODEC_OPUS) {
        int err;
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

    char buf[SOCKET_BUFSIZE] = HANDSHAKE_MAGIC_STRING;
    size_t buflen = sizeof(buf);

    char *ptr = buf + HANDSHAKE_MAGIC_STRING_LEN;
    char *tail = buf + buflen;
    packet_config_t config = {.flags = flags};
    ptr += packet_config_write(ptr, tail - ptr, &config);

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
            send_heartbeat(sock, ctx.idx);
            time(&timer);
        }

        int res = recv(sock, buf, buflen, 0);
        if (res < 0 && !socket_error_timeout()) {
            log_fatal("Failed to receive packet: %s", socket_strerror());
            break;
        }
        time((time_t *)&ctx.timer);

        if (res < 1)
            continue;

        const char *ptr = buf;
        const char *tail = buf + res;
        switch (*ptr++) {
        case PACKET_TYPE_DATA:
            handle_data(&ctx, ptr, tail - ptr);
            break;
        case PACKET_TYPE_CLOSE:
            running = false;
            break;
        }
    }

    packet_client_header_t hdr = {
        .idx = ctx.idx,
        .type = PACKET_TYPE_CLOSE,
    };
    if (send(sock, (char *)&hdr, sizeof(hdr), 0) < 0)
        log_error("Failed to send close packet: %s", socket_strerror());
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

    return rc;
}

noreturn static void usage(int rc) {
    fprintf(stderr,
            "Usage: ongaku-client [-pdiofx] <server-addr>\n"
            "   -h              print this help\n"
            "   -p port         use different port to connect to the server\n"
            "   -d direction    specifiy direction of the stream: in, out, duplex\n"
            "   -i device       use input device name\n"
            "   -o device       use output device name\n"
            "   -f              use 32-bit float sample format\n"
            "   -x              disable Opus codec (will cause significantly higher network bandwidth)\n");
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    log_init();

    const char *message;
    int rc = EXIT_SUCCESS;
    const char *indev = NULL;
    const char *outdev = NULL;
    uint16_t port = DEFAULT_PORT;
    int flags = DEFAULT_STREAMCFG_FLAGS;

    int opt;
    while ((opt = getopt(argc, argv, "hp:d:i:o:fx")) != -1) {
        switch (opt) {
        case 'h':
            usage(EXIT_SUCCESS);
        case 'p':
            port = atoi(optarg);
            break;
        case 'd':
            if (strncasecmp(optarg, "in", 2) == 0)
                flags &= ~STREAMCFG_FLAG_OUTPUT;
            else if (strncasecmp(optarg, "out", 3) == 0)
                flags &= ~STREAMCFG_FLAG_INPUT;
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
        case 'x':
            flags &= ~STREAMCFG_FLAG_CODEC_OPUS;
            break;
        default:
            usage(EXIT_FAILURE);
        }
    }
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

    if (socket_init(&message)) {
        log_fatal("Failed to initialize socket: %s", message);
        goto fail;
    }
    if (audio_init(&message)) {
        log_fatal("Failed to initialize audio: %s", message);
        goto fail;
    }

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

    ringbuf_t *rb = ringbuf_new(audio_stream_frame_bufsize(&params, FRAME_BUFFER_DURATION));
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
