#include "log.h"

#include <pulse/pulseaudio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define SAMPLE_SIZE sizeof(int16_t)
#define FRAME_DURATION_MS 2.5

static int sockets[2];
static pa_sample_spec spec = {
    .channels = 2,
    .format = PA_SAMPLE_S16LE,
    .rate = 48000,
};

typedef enum {
    APP_STATE_INIT,
    APP_STATE_MAINLOOP_STARTED,
    APP_STATE_CONTEXT_CONNECTED,
    APP_STATE_CONTEXT_READY,
    APP_STATE_STREAM_CONNECTED,
    APP_STATE_SOCKETS_CREATED,
    APP_STATE_SOCKETS_LISTENING,
    APP_STATE_FINISHED,
} app_state_t;

void log_error_pa_context(pa_context *context, const char *message) {
    const char *cause = pa_strerror(pa_context_errno(context));
    log_error("%s: %s", message, cause);
}

void on_context_state(pa_context *context, void *userdata) {
    pa_threaded_mainloop *mainloop = userdata;
    pa_threaded_mainloop_signal(mainloop, 0);
}

void on_stream_read(pa_stream *stream, size_t nbytes, void *userdata) {
    const void *data;
    if (pa_stream_peek(stream, &data, &nbytes) || nbytes <= 0) {
        return;
    }
    pa_stream_drop(stream);
    fwrite(data, nbytes, 1, stdout);
}

void on_signal(int signal) {
    send(sockets[1], "", 0, 0);
}

int main() {
    int rc = EXIT_SUCCESS;
    app_state_t state = APP_STATE_INIT;
    int locked = 0;

    pa_threaded_mainloop *mainloop = pa_threaded_mainloop_new();
    pa_mainloop_api *api = pa_threaded_mainloop_get_api(mainloop);
    pa_context *context = pa_context_new(api, "Ongaku");
    pa_stream *stream = pa_stream_new(context, "Ongaku Input", &spec, NULL);

    pa_context_set_state_callback(context, on_context_state, mainloop);
    pa_stream_set_read_callback(stream, on_stream_read, NULL);

    if (pa_threaded_mainloop_start(mainloop)) {
        log_error("Failed to start mainloop");
        goto error;
    }
    state = APP_STATE_MAINLOOP_STARTED;

    pa_threaded_mainloop_lock(mainloop);
    locked = 1;

    if (pa_context_connect(context, NULL, 0, NULL)) {
        log_error_pa_context(context, "Failed to connect context");
        goto error;
    }
    state = APP_STATE_CONTEXT_CONNECTED;

    while (state < APP_STATE_CONTEXT_READY) {
        pa_threaded_mainloop_wait(mainloop);
        pa_context_state_t ctx_state = pa_context_get_state(context);
        if (ctx_state == PA_CONTEXT_READY)
            state = APP_STATE_CONTEXT_READY;
    }

    pa_buffer_attr attr = {.maxlength = FRAME_DURATION_MS * SAMPLE_SIZE * spec.channels * spec.rate / 1e3};
    if (pa_stream_connect_record(stream, NULL, &attr, 0)) {
        log_error_pa_context(context, "Failed to start stream");
        goto error;
    }
    state = APP_STATE_STREAM_CONNECTED;

    pa_threaded_mainloop_unlock(mainloop);
    locked = 0;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets)) {
        perror("Failed to create socket pair");
        goto error;
    }
    state = APP_STATE_SOCKETS_CREATED;

    signal(SIGTERM, on_signal);
    state = APP_STATE_SOCKETS_LISTENING;

    recv(sockets[0], NULL, 0, 0);
    state = APP_STATE_FINISHED;

    goto cleanup;

error:
    rc = EXIT_FAILURE;

cleanup:
    if (!locked)
        pa_threaded_mainloop_lock(mainloop);
    if (state >= APP_STATE_STREAM_CONNECTED)
        pa_stream_disconnect(stream);
    if (state >= APP_STATE_CONTEXT_CONNECTED)
        pa_context_disconnect(context);
    pa_threaded_mainloop_unlock(mainloop);
    if (state >= APP_STATE_MAINLOOP_STARTED)
        pa_threaded_mainloop_stop(mainloop);
    pa_threaded_mainloop_free(mainloop);
    if (state >= APP_STATE_SOCKETS_CREATED) {
        for (int i = 0; i < 2; i++)
            close(sockets[i]);
    }

    return rc;
}
