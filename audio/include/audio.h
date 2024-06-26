#ifndef _AUDIO_H
#define _AUDIO_H

#include <stddef.h>

#define CHANNELS 2
#define SAMPLE_RATE 48000
#define FRAME_PACKET_DURATION 0.01
#define FRAME_BUFFER_DURATION 0.25

#define SAMPLE_FORMAT short
#define SAMPLE_SIZE sizeof(SAMPLE_FORMAT)

#define OPUS_APPLICATION OPUS_APPLICATION_RESTRICTED_LOWDELAY

typedef enum audio_format {
    AUDIO_FORMAT_S16,
    AUDIO_FORMAT_F32,
} audio_format_t;

typedef struct {
    const char *application_name;
    int channels;
    double sample_rate;
    size_t sample_size;
    audio_format_t sample_format;
    double frame_duration;
} audio_stream_params_t;

#define DEFAULT_AUDIO_STREAM_PARAMS(name) \
    { \
        .application_name = name, \
        .channels = CHANNELS, \
        .sample_rate = SAMPLE_RATE, \
        .sample_size = SAMPLE_SIZE, \
        .sample_format = AUDIO_FORMAT_S16, \
        .frame_duration = FRAME_PACKET_DURATION, \
    };

typedef struct audio_stream audio_stream_t;

typedef enum audio_stream_state {
    AUDIO_STREAM_INIT,
    AUDIO_STREAM_DISCONNECTED,
    AUDIO_STREAM_CONNECTED,
    AUDIO_STREAM_RUNNING,
} audio_stream_state_t;

typedef enum audio_callback_result {
    AUDIO_STREAM_CONTINUE,
    AUDIO_STREAM_COMPLETE,
    AUDIO_STREAM_ABORT,
} audio_callback_result_t;

typedef audio_callback_result_t (*audio_playback_callback_t)(void *data, size_t *len, void *userdata);
typedef audio_callback_result_t (*audio_record_callback_t)(const void *data, size_t len, void *userdata);
typedef void (*audio_error_callback_t)(const char *message, void *userdata);
typedef void (*audio_finished_callback_t)(void *userdata);

size_t audio_stream_frame_size(const audio_stream_params_t *params);
size_t audio_stream_frame_count(const audio_stream_params_t *params, double duration);
size_t audio_stream_frame_bufsize(const audio_stream_params_t *params, double duration);

int audio_init(const char **message);
int audio_terminate(const char **message);

audio_stream_t *audio_stream_new(const audio_stream_params_t *params);
void audio_stream_init(audio_stream_t *stream, const audio_stream_params_t *params);
audio_stream_state_t audio_stream_get_state(audio_stream_t *stream);
int audio_stream_connect(audio_stream_t *stream, const char **message);
int audio_stream_open_record(audio_stream_t *stream,
                             const char *dev,
                             const char *name,
                             audio_record_callback_t record_cb,
                             audio_error_callback_t error_cb,
                             audio_finished_callback_t finished_cb,
                             void *userdata,
                             const char **message);
int audio_stream_open_playback(audio_stream_t *stream,
                               const char *dev,
                               const char *name,
                               audio_playback_callback_t playback_cb,
                               audio_error_callback_t error_cb,
                               audio_finished_callback_t finished_cb,
                               void *userdata,
                               const char **message);
int audio_stream_start(audio_stream_t *stream, const char **message);
int audio_stream_stop(audio_stream_t *stream, const char **message);
int audio_stream_close_record(audio_stream_t *stream, const char **message);
int audio_stream_close_playback(audio_stream_t *stream, const char **message);
int audio_stream_disconnect(audio_stream_t *stream, const char **message);
void audio_stream_deinit(audio_stream_t *stream);
void audio_stream_free(audio_stream_t *stream);
size_t audio_stream_sizeof();

#endif
