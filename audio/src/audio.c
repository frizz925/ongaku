#include "audio.h"

size_t audio_stream_frame_size(const audio_stream_params_t *params) {
    return params->channels * params->sample_size;
}

size_t audio_stream_frame_count(const audio_stream_params_t *params, double duration) {
    return duration * params->channels * params->sample_rate;
}

size_t audio_stream_frame_bufsize(const audio_stream_params_t *params, double duration) {
    return audio_stream_frame_count(params, duration) * params->sample_size;
}
