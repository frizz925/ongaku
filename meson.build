project('ongaku', 'c')
compiler = meson.get_compiler('c')
inc_dir = include_directories('include')

audio_src = ['src/audio.c']
audio_deps = []
if host_machine.system() == 'linux'
    pulse = compiler.find_library('pulse')
    audio_src += 'src/platform/pulseaudio.c'
    audio_deps += pulse

    executable(
        'ongaku-pulse',
        sources: ['src/log.c', 'src/pulse.c'],
        dependencies: pulse,
        include_directories: inc_dir,
    )
else
    audio_src += 'src/platform/portaudio.c'
    audio_deps += compiler.find_library('portaudio')
endif

audio = library(
    'ongakuaudio',
    sources: audio_src,
    dependencies: audio_deps,
    include_directories: inc_dir,
    install: true,
)

core_src = [
    'src/log.c',
    'src/pool.c',
    'src/protocol.c',
    'src/ringbuf.c',
    'src/socket.c',
]
core_deps = []
core_libs = [audio]

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
    include_directories: inc_dir,
    install: true,
)
common_libs = [audio, core]

executable(
    'ongaku-server',
    sources: common_src + 'src/server.c',
    dependencies: common_deps,
    link_with: common_libs,
    include_directories: inc_dir,
    install: true,
)

executable(
    'ongaku-client',
    sources: common_src + 'src/client.c',
    dependencies: common_deps,
    link_with: common_libs,
    include_directories: inc_dir,
    install: true,
)

test(
    'pool test',
    executable(
        'test_pool',
        sources: ['src/pool.c', 'tests/test_pool.c'],
        include_directories: inc_dir,
    ),
)

test(
    'ringbuf test',
    executable(
        'test_ringbuf',
        sources: ['src/ringbuf.c', 'tests/test_ringbuf.c'],
        include_directories: inc_dir,
    ),
)