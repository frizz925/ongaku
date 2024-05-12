audio_src = ['src/audio.c']
audio_deps = []
if host_machine.system() == 'linux'
    audio_src += 'src/platform/pulseaudio.c'
    audio_deps += cc.find_library('pulse')
else
    audio_src += 'src/platform/portaudio.c'
    audio_deps += cc.find_library('portaudio')
endif
audio_include = include_directories('include')

audio = library(
    'ongakuaudio',
    sources: audio_src,
    dependencies: audio_deps,
    include_directories: [util_include, audio_include],
    install: true,
)