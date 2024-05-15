#include "audio.h"
#include "util.h"

#include <pulse/pulseaudio.h>

#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STREAM_DIRECTION_IN 1
#define STREAM_DIRECTION_OUT 2

#define STREAM_CONTEXT_FIELDS \
    atomic_int refcount; \
    atomic_bool running; \
    int direction; \
    pa_stream *pa_stream; \
    audio_stream_t *stream; \
    audio_error_callback_t error_cb; \
    audio_finished_callback_t finished_cb; \
    void *userdata;

#define STREAM_ERROR(ctx, message) \
    if (ctx->error_cb != NULL) \
        ctx->error_cb(message, ctx->userdata);

#define STREAM_FLAGS PA_STREAM_ADJUST_LATENCY

static pa_threaded_mainloop *mainloop = NULL;
static atomic_int lock_count = 0;

typedef struct {
    STREAM_CONTEXT_FIELDS
} stream_context_t;

typedef struct {
    STREAM_CONTEXT_FIELDS
    audio_record_callback_t record_cb;
} record_context_t;

typedef struct {
    STREAM_CONTEXT_FIELDS
    audio_playback_callback_t playback_cb;
} playback_context_t;

struct audio_stream {
    atomic_bool connected;
    atomic_int lock_count;

    pa_sample_spec sample_spec;
    pa_buffer_attr buffer_attr;

    pa_context *pa_context;

    record_context_t record;
    playback_context_t playback;
};

static void on_context_state(pa_context *context, void *userdata) {
    switch (pa_context_get_state(context)) {
    case PA_CONTEXT_READY:
    case PA_CONTEXT_TERMINATED:
    case PA_CONTEXT_FAILED:
        pa_threaded_mainloop_signal((pa_threaded_mainloop *)userdata, 0);
    default:
        break;
    }
}

static int context_stop(stream_context_t *ctx, const char **message);
static void context_deinit(stream_context_t *ctx);

static void on_stream_read(pa_stream *stream, size_t nbytes, void *userdata) {
    int err;
    const char *message;
    const void *data;
    audio_callback_result_t result = AUDIO_STREAM_CONTINUE;
    record_context_t *ctx = userdata;

    if (!ctx->running)
        return;
    if ((err = pa_stream_peek(stream, &data, &nbytes))) {
        STREAM_ERROR(ctx, pa_strerror(err));
        goto end;
    }
    if (nbytes <= 0)
        return;
    if (data)
        result = ctx->record_cb(data, nbytes, ctx->userdata);
    if (result == AUDIO_STREAM_CONTINUE && (err = pa_stream_drop(stream)) != 0)
        STREAM_ERROR(ctx, pa_strerror(err));

end:
    if (err != 0)
        result = AUDIO_STREAM_ABORT;

    switch (result) {
    case AUDIO_STREAM_COMPLETE:
    case AUDIO_STREAM_ABORT:
        if (context_stop((stream_context_t *)ctx, &message))
            STREAM_ERROR(ctx, message);
        break;
    case AUDIO_STREAM_CONTINUE:
        break;
    }
}

static void on_stream_write(pa_stream *stream, size_t nbytes, void *userdata) {
    int err;
    const char *message;
    void *data;
    audio_callback_result_t result;
    playback_context_t *ctx = (playback_context_t *)userdata;

    if (!ctx->running)
        return;
    if ((err = pa_stream_begin_write(stream, &data, &nbytes))) {
        STREAM_ERROR(ctx, pa_strerror(err));
        goto end;
    }
    result = ctx->playback_cb(data, &nbytes, ctx->userdata);
    if (result == AUDIO_STREAM_CONTINUE && nbytes > 0) {
        if ((err = pa_stream_write(stream, data, nbytes, NULL, 0, PA_SEEK_RELATIVE)))
            STREAM_ERROR(ctx, pa_strerror(err));
    } else {
        if ((err = pa_stream_cancel_write(stream)))
            STREAM_ERROR(ctx, pa_strerror(err));
    }

end:
    if (err != 0)
        result = AUDIO_STREAM_ABORT;

    switch (result) {
    case AUDIO_STREAM_COMPLETE:
    case AUDIO_STREAM_ABORT:
        if (context_stop((stream_context_t *)ctx, &message))
            ctx->error_cb(message, ctx->userdata);
        break;
    case AUDIO_STREAM_CONTINUE:
        break;
    }
}

static void on_stream_state(pa_stream *stream, void *userdata) {
    stream_context_t *ctx = userdata;
    switch (pa_stream_get_state(stream)) {
    case PA_STREAM_UNCONNECTED:
    case PA_STREAM_CREATING:
    case PA_STREAM_READY:
        /* Do nothing */
        break;
    default:
        if (ctx->finished_cb)
            ctx->finished_cb(ctx->userdata);
        context_deinit(ctx);
        break;
    }
}

static inline void mainloop_lock() {
    pa_threaded_mainloop_lock(mainloop);
    lock_count++;
}

static inline void mainloop_unlock() {
    if (lock_count <= 0)
        return;
    pa_threaded_mainloop_unlock(mainloop);
    lock_count--;
}

static inline void mainloop_unlock_all() {
    while (lock_count > 0)
        mainloop_unlock();
}

static void context_init(stream_context_t *context,
                         int direction,
                         const char *name,
                         audio_error_callback_t error_cb,
                         audio_finished_callback_t finished_cb,
                         void *userdata,
                         const char **message) {
    audio_stream_t *stream = context->stream;
    context->refcount = 0;
    context->direction = direction;
    context->pa_stream = pa_stream_new(stream->pa_context, name, &stream->sample_spec, NULL);
    context->error_cb = error_cb;
    context->finished_cb = finished_cb;
    context->userdata = userdata;
    pa_stream_set_state_callback(context->pa_stream, on_stream_state, context);
}

static int context_start(stream_context_t *ctx, const char **message) {
    if (ctx->running || !ctx->pa_stream)
        return 0;
    audio_stream_t *stream = ctx->stream;
    int err = ctx->direction == STREAM_DIRECTION_IN
                  ? pa_stream_connect_record(ctx->pa_stream, NULL, &stream->buffer_attr, STREAM_FLAGS)
                  : pa_stream_connect_playback(ctx->pa_stream, NULL, &stream->buffer_attr, STREAM_FLAGS, NULL, NULL);
    if (err) {
        SET_MESSAGE(message, pa_strerror(err));
        return -1;
    }
    ctx->refcount++;
    ctx->running = true;
    return 0;
}

static int context_stop(stream_context_t *ctx, const char **message) {
    if (!ctx->running || !ctx->pa_stream)
        return 0;
    int err = pa_stream_disconnect(ctx->pa_stream);
    if (err) {
        SET_MESSAGE(message, pa_strerror(err));
        return -1;
    }
    ctx->running = false;
    return 0;
}

static void context_deinit(stream_context_t *context) {
    if (context->refcount > 0) {
        context->refcount--;
        return;
    }

    if (context->pa_stream)
        pa_stream_unref(context->pa_stream);

    context->refcount = 0;
    context->pa_stream = NULL;
    context->error_cb = NULL;
    context->userdata = NULL;
}

int audio_init(const char **message) {
    int err;
    if (mainloop)
        return 0;
    mainloop = pa_threaded_mainloop_new();
    if ((err = pa_threaded_mainloop_start(mainloop))) {
        SET_MESSAGE(message, pa_strerror(err));
        return -1;
    }
    return 0;
}

int audio_terminate(const char **message) {
    if (!mainloop)
        return 0;
    mainloop_unlock_all();
    pa_threaded_mainloop_stop(mainloop);
    pa_threaded_mainloop_free(mainloop);
    mainloop = NULL;
    return 0;
}

audio_stream_t *audio_stream_new(const audio_stream_params_t *params) {
    audio_stream_t *stream = malloc(audio_stream_sizeof());
    audio_stream_init(stream, params);
    return stream;
}

void audio_stream_init(audio_stream_t *stream, const audio_stream_params_t *params) {
    assert(mainloop != NULL);
    mainloop_lock();
    memset(stream, 0, audio_stream_sizeof());

    stream->sample_spec.format = params->sample_format == AUDIO_FORMAT_F32 ? PA_SAMPLE_FLOAT32LE : PA_SAMPLE_S16LE;
    stream->sample_spec.channels = params->channels;
    stream->sample_spec.rate = params->sample_rate;

    size_t bufsize = audio_stream_frame_bufsize(params, params->frame_duration);
    stream->buffer_attr.maxlength = bufsize;
    stream->buffer_attr.tlength = (uint32_t)-1;
    stream->buffer_attr.prebuf = (uint32_t)-1;
    stream->buffer_attr.minreq = (uint32_t)-1;
    stream->buffer_attr.fragsize = (uint32_t)-1;

    pa_mainloop_api *api = pa_threaded_mainloop_get_api(mainloop);
    stream->pa_context = pa_context_new(api, params->application_name);
    pa_context_set_state_callback(stream->pa_context, on_context_state, mainloop);

    stream->record.stream = stream;
    stream->playback.stream = stream;
    mainloop_unlock();
}

audio_stream_state_t audio_stream_get_state(audio_stream_t *stream) {
    if (stream->record.running)
        return AUDIO_STREAM_RUNNING;
    if (stream->playback.running)
        return AUDIO_STREAM_RUNNING;
    if (stream->connected)
        return AUDIO_STREAM_CONNECTED;
    return AUDIO_STREAM_DISCONNECTED;
}

int audio_stream_connect(audio_stream_t *stream, const char **message) {
    int err;
    if (stream->connected)
        return 0;

    mainloop_lock();
    if ((err = pa_context_connect(stream->pa_context, NULL, 0, NULL)))
        goto fail;

    while (pa_context_get_state(stream->pa_context) != PA_CONTEXT_READY)
        pa_threaded_mainloop_wait(mainloop);

    stream->connected = true;
    mainloop_unlock();
    return 0;

fail:
    SET_MESSAGE(message, pa_strerror(err));
    mainloop_unlock();
    return -1;
}

int audio_stream_open_record(audio_stream_t *stream,
                             const char *dev,
                             const char *name,
                             audio_record_callback_t record_cb,
                             audio_error_callback_t error_cb,
                             audio_finished_callback_t finished_cb,
                             void *userdata,
                             const char **message) {
    mainloop_lock();
    context_init(
        (stream_context_t *)&stream->record, STREAM_DIRECTION_IN, name, error_cb, finished_cb, userdata, message);
    pa_stream_set_read_callback(stream->record.pa_stream, on_stream_read, &stream->record);
    stream->record.record_cb = record_cb;
    mainloop_unlock();
    return 0;
}

int audio_stream_open_playback(audio_stream_t *stream,
                               const char *dev,
                               const char *name,
                               audio_playback_callback_t playback_cb,
                               audio_error_callback_t error_cb,
                               audio_finished_callback_t finished_cb,
                               void *userdata,
                               const char **message) {
    mainloop_lock();
    context_init(
        (stream_context_t *)&stream->playback, STREAM_DIRECTION_OUT, name, error_cb, finished_cb, userdata, message);
    pa_stream_set_write_callback(stream->playback.pa_stream, on_stream_write, &stream->playback);
    stream->playback.playback_cb = playback_cb;
    mainloop_unlock();
    return 0;
}

int audio_stream_start(audio_stream_t *stream, const char **message) {
    mainloop_lock();
    int res = 0;
    if (context_start((stream_context_t *)&stream->record, message))
        res = -1;
    if (context_start((stream_context_t *)&stream->playback, message))
        res = -1;
    mainloop_unlock();
    return res;
}

int audio_stream_stop(audio_stream_t *stream, const char **message) {
    mainloop_lock();
    int res = 0;
    if (context_stop((stream_context_t *)&stream->record, message))
        res = -1;
    if (context_stop((stream_context_t *)&stream->playback, message))
        res = -1;
    mainloop_unlock();
    return res;
}

int audio_stream_close_record(audio_stream_t *stream, const char **message) {
    mainloop_lock();
    context_deinit((stream_context_t *)&stream->record);
    mainloop_unlock();
    return 0;
}

int audio_stream_close_playback(audio_stream_t *stream, const char **message) {
    mainloop_lock();
    context_deinit((stream_context_t *)&stream->playback);
    mainloop_unlock();
    return 0;
}

int audio_stream_disconnect(audio_stream_t *stream, const char **message) {
    if (!stream->connected)
        return 0;
    mainloop_lock();
    pa_context_disconnect(stream->pa_context);
    stream->connected = false;
    mainloop_unlock();
    return 0;
}

void audio_stream_deinit(audio_stream_t *stream) {
    mainloop_lock();
    if (stream->pa_context)
        pa_context_unref(stream->pa_context);

    stream->record.pa_stream = NULL;
    stream->playback.pa_stream = NULL;
    stream->pa_context = NULL;
    mainloop_unlock();
}

void audio_stream_free(audio_stream_t *stream) {
    audio_stream_deinit(stream);
    free(stream);
}

size_t audio_stream_sizeof() {
    return sizeof(audio_stream_t);
}
