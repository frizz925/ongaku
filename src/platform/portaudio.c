#include "../audio.h"
#include "../util.h"

#include <portaudio.h>

#include <stdbool.h>
#include <stdio.h>

static PaHostApiIndex host_api = paHostApiNotFound;

#define CONTEXT_FIELDS \
    bool running; \
    audio_stream_t *stream; \
    PaStreamParameters pa_params; \
    PaStream *pa_stream; \
    audio_finished_callback_t finished_cb; \
    void *userdata;

typedef enum {
    DIRECTION_IN,
    DIRECTION_OUT,
} audio_direction_t;

typedef struct {
    CONTEXT_FIELDS
} stream_context_t;

typedef struct {
    CONTEXT_FIELDS
    audio_playback_callback_t playback_cb;
} playback_context_t;

typedef struct {
    CONTEXT_FIELDS
    audio_record_callback_t record_cb;
} record_context_t;

struct audio_stream {
    bool connected;
    audio_stream_params_t params;
    size_t frame_count;
    playback_context_t playback;
    record_context_t record;
};

static int stream_callback_result_to_pa(audio_callback_result_t result) {
    switch (result) {
    case AUDIO_STREAM_ABORT:
        return paAbort;
    case AUDIO_STREAM_COMPLETE:
        return paComplete;
    case AUDIO_STREAM_CONTINUE:
        return paContinue;
    }
}

static int on_stream_input(const void *input,
                           void *output,
                           unsigned long frame_count,
                           const PaStreamCallbackTimeInfo *tinfo,
                           PaStreamCallbackFlags flags,
                           void *userdata) {
    record_context_t *ctx = userdata;
    const audio_stream_params_t *params = &ctx->stream->params;
    size_t len = frame_count * params->channels * params->sample_size;
    audio_callback_result_t result = ctx->record_cb(input, len, ctx->userdata);
    return stream_callback_result_to_pa(result);
}

static int on_stream_output(const void *input,
                            void *output,
                            unsigned long frame_count,
                            const PaStreamCallbackTimeInfo *tinfo,
                            PaStreamCallbackFlags flags,
                            void *userdata) {
    playback_context_t *ctx = userdata;
    const audio_stream_params_t *params = &ctx->stream->params;
    size_t len = frame_count * params->channels * params->sample_size;
    size_t res = len;
    audio_callback_result_t result = ctx->playback_cb(output, &res, ctx->userdata);
    size_t left = len - res;
    if (left > 0)
        memset(output + res, 0, left);
    return stream_callback_result_to_pa(result);
}

static void on_stream_finished(void *userdata) {
    stream_context_t *ctx = userdata;
    if (ctx->finished_cb)
        ctx->finished_cb(ctx->userdata);
}

static PaDeviceIndex find_device(const char *dev, const audio_stream_params_t *params, audio_direction_t direction) {
    if (!dev)
        return direction == DIRECTION_IN ? Pa_GetDefaultInputDevice() : Pa_GetDefaultOutputDevice();
    size_t devlen = strlen(dev);
    for (PaDeviceIndex idx = 0; idx < Pa_GetDeviceCount(); idx++) {
        const PaDeviceInfo *info = Pa_GetDeviceInfo(idx);
        if (host_api != paHostApiNotFound && info->hostApi != host_api)
            continue;
        if (strncmp(info->name, dev, devlen))
            continue;
        if (direction == DIRECTION_IN && info->maxInputChannels < params->channels)
            continue;
        if (direction == DIRECTION_OUT && info->maxOutputChannels < params->channels)
            continue;
        return idx;
    }
    return paNoDevice;
}

static void stream_context_reset(stream_context_t *ctx, audio_stream_t *stream) {
    memset(ctx, 0, sizeof(stream_context_t));
    ctx->stream = stream;
    ctx->pa_params.channelCount = stream->params.channels;

    switch (stream->params.sample_format) {
    case AUDIO_FORMAT_S16:
        ctx->pa_params.sampleFormat = paInt16;
        break;
    case AUDIO_FORMAT_F32:
        ctx->pa_params.sampleFormat = paFloat32;
        break;
    }
}

static int context_init(stream_context_t *ctx,
                        PaDeviceIndex idx,
                        audio_direction_t direction,
                        audio_finished_callback_t finished_cb,
                        void *userdata,
                        const char **message) {
    audio_stream_t *stream = ctx->stream;
    const audio_stream_params_t *params = &stream->params;
    const PaDeviceInfo *info = Pa_GetDeviceInfo(idx);
    fprintf(stderr, "Using %s device: %s\n", direction == DIRECTION_IN ? "input" : "output", info->name);
    ctx->pa_params.device = idx;
    ctx->pa_params.suggestedLatency =
        direction == DIRECTION_IN ? info->defaultLowInputLatency : info->defaultLowOutputLatency;
    ctx->finished_cb = finished_cb;
    ctx->userdata = userdata;
    PaError err = Pa_OpenStream(&ctx->pa_stream,
                                direction == DIRECTION_IN ? &ctx->pa_params : NULL,
                                direction == DIRECTION_OUT ? &ctx->pa_params : NULL,
                                params->sample_rate,
                                stream->frame_count,
                                0,
                                direction == DIRECTION_IN ? on_stream_input : on_stream_output,
                                ctx);
    if (err) {
        SET_MESSAGE(message, Pa_GetErrorText(err));
        return -1;
    }
    Pa_SetStreamFinishedCallback(ctx->pa_stream, on_stream_finished);
    return 0;
}

static int context_start(stream_context_t *ctx, const char **message) {
    PaError err;
    if (ctx->running || !ctx->pa_stream)
        return 0;
    if ((err = Pa_StartStream(ctx->pa_stream)) != paNoError) {
        SET_MESSAGE(message, Pa_GetErrorText(err));
        return -1;
    }
    ctx->running = true;
    return 0;
}

static int context_stop(stream_context_t *ctx, const char **message) {
    PaError err;
    if (!ctx->running || !ctx->pa_stream)
        return 0;
    if ((err = Pa_StopStream(ctx->pa_stream)) != paNoError) {
        SET_MESSAGE(message, Pa_GetErrorText(err));
        return -1;
    }
    ctx->running = false;
    return 0;
}

static int context_deinit(stream_context_t *ctx, const char **message) {
    if (ctx->pa_stream) {
        PaError err = Pa_CloseStream(ctx->pa_stream);
        if (err) {
            SET_MESSAGE(message, Pa_GetErrorText(err));
            return -1;
        }
    }
    ctx->pa_stream = NULL;
    ctx->pa_params.device = paNoDevice;
    ctx->pa_params.suggestedLatency = 0;
    ctx->userdata = NULL;
    return 0;
}

int audio_init(const char **message) {
    PaError err = Pa_Initialize();
    if (err != paNoError) {
        SET_MESSAGE(message, Pa_GetErrorText(err));
        return -1;
    }
#ifdef _WIN32
    for (PaHostApiIndex idx = 0; idx < Pa_GetHostApiCount(); idx++) {
        const char *api_name = Pa_GetHostApiInfo(idx)->name;
        if (strncmp(api_name, "Windows WASAPI", strlen(api_name)) == 0) {
            host_api = idx;
            break;
        }
    }
#endif
    return 0;
}

int audio_terminate(const char **message) {
    PaError err = Pa_Terminate();
    if (err != paNoError) {
        SET_MESSAGE(message, Pa_GetErrorText(err));
        return -1;
    }
    return 0;
}

audio_stream_t *audio_stream_new(const audio_stream_params_t *params) {
    audio_stream_t *stream = malloc(audio_stream_sizeof());
    audio_stream_init(stream, params);
    return stream;
}

void audio_stream_init(audio_stream_t *stream, const audio_stream_params_t *params) {
    memset(stream, 0, audio_stream_sizeof());
    stream->connected = false;
    stream->params = *params;
    stream->frame_count = audio_stream_frame_count(params, params->frame_duration);
    stream_context_reset((stream_context_t *)&stream->playback, stream);
    stream_context_reset((stream_context_t *)&stream->record, stream);
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
    return 0;
}

int audio_stream_open_record(audio_stream_t *stream,
                             const char *dev,
                             const char *name,
                             audio_record_callback_t record_cb,
                             audio_error_callback_t error_cb,
                             audio_finished_callback_t finished_cb,
                             void *userdata,
                             const char **message) {
    assert(record_cb != NULL);
    PaDeviceIndex idx = dev ? find_device(dev, &stream->params, DIRECTION_IN) : Pa_GetDefaultInputDevice();
    if (idx == paNoDevice) {
        SET_MESSAGE(message, "Input device not found");
        return -1;
    }
    if (context_init((stream_context_t *)&stream->record, idx, DIRECTION_IN, finished_cb, userdata, message))
        return -1;
    stream->record.record_cb = record_cb;
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
    assert(playback_cb != NULL);
    PaDeviceIndex idx = dev ? find_device(dev, &stream->params, DIRECTION_OUT) : Pa_GetDefaultOutputDevice();
    if (idx == paNoDevice) {
        SET_MESSAGE(message, "Output device not found");
        return -1;
    }
    if (context_init((stream_context_t *)&stream->playback, idx, DIRECTION_OUT, finished_cb, userdata, message))
        return -1;
    stream->playback.playback_cb = playback_cb;
    return 0;
}

int audio_stream_start(audio_stream_t *stream, const char **message) {
    if (context_start((stream_context_t *)&stream->record, message))
        return -1;
    if (context_start((stream_context_t *)&stream->playback, message))
        return -1;
    return 0;
}

int audio_stream_stop(audio_stream_t *stream, const char **message) {
    if (context_stop((stream_context_t *)&stream->record, message))
        return -1;
    if (context_stop((stream_context_t *)&stream->playback, message))
        return -1;
    return 0;
}

int audio_stream_close_record(audio_stream_t *stream, const char **message) {
    if (context_deinit((stream_context_t *)&stream->record, message))
        return -1;
    stream->record.record_cb = NULL;
    return 0;
}

int audio_stream_close_playback(audio_stream_t *stream, const char **message) {
    if (context_deinit((stream_context_t *)&stream->playback, message))
        return -1;
    stream->playback.playback_cb = NULL;
    return 0;
}

int audio_stream_disconnect(audio_stream_t *stream, const char **message) {
    if (!stream->connected)
        return 0;
    stream->connected = false;
    return 0;
}

void audio_stream_deinit(audio_stream_t *stream) {
    audio_stream_params_t empty_params = {0};
    stream->params = empty_params;
    stream->frame_count = 0;
}

void audio_stream_free(audio_stream_t *stream) {
    audio_stream_deinit(stream);
    free(stream);
}

size_t audio_stream_sizeof() {
    return sizeof(audio_stream_t);
}
