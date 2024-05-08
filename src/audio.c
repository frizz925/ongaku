#include "audio.h"

size_t audio_stream_sample_count(const audio_stream_params_t *params) {
    return params->sample_rate / 1e3;
}

size_t audio_stream_frame_count(const audio_stream_params_t *params) {
    return params->frame_duration * audio_stream_sample_count(params);
}

size_t audio_stream_frame_size(const audio_stream_params_t *params) {
    return params->channels * params->sample_size;
}

size_t audio_stream_frame_bufsize(const audio_stream_params_t *params) {
    return audio_stream_frame_count(params) * audio_stream_frame_size(params);
}
