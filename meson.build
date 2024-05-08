project('ongaku', 'c')
compiler = meson.get_compiler('c')

core_src = [
    'src/log.c',
    'src/pool.c',
    'src/protocol.c',
    'src/ringbuf.c',
    'src/socket.c',
]
core_deps = []

audio_src = ['src/audio.c']
audio_deps = []
if host_machine.system() == 'linux'
    audio_src += 'src/platform/pulseaudio.c'
    audio_deps += compiler.find_library('pulse')
else
    audio_src += 'src/platform/portaudio.c'
    audio_deps += compiler.find_library('portaudio')
endif

common_src = ['src/callbacks.c']
common_deps = [compiler.find_library('opus')]

if host_machine.system() == 'windows'
    ws2_32 = compiler.find_library('ws2_32')
    core_deps += ws2_32
    common_deps += ws2_32
endif

core = library(
    'ongakucore',
    sources: core_src,
    dependencies: core_deps,
    install: true,
)
audio = library(
    'ongakuaudio',
    sources: audio_src,
    dependencies: audio_deps,
    install: true,
)
common_libs = [core, audio]

if host_machine.system() == 'linux'
    pulse = compiler.find_library('pulse')
    executable(
        'ongaku-pulse',
        sources: ['src/log.c', 'src/pulse.c'],
        dependencies: pulse,
    )
endif

executable(
    'ongaku-server',
    sources: common_src + 'src/server.c',
    dependencies: common_deps,
    link_with: common_libs,
    install: true,
)

executable(
    'ongaku-client',
    sources: common_src + 'src/client.c',
    dependencies: common_deps,
    link_with: common_libs,
    install: true,
)