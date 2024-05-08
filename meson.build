project('ongaku', 'c')
compiler = meson.get_compiler('c')

lib_src = [
    'src/audio.c',
    'src/log.c',
    'src/pool.c',
    'src/protocol.c',
    'src/ringbuf.c',
    'src/socket.c',
]
lib_deps = []
if host_machine.system() == 'linux'
    lib_src += 'src/platform/pulseaudio.c'
    lib_deps += compiler.find_library('pulse')
else
    lib_src += 'src/platform/portaudio.c'
    lib_deps += compiler.find_library('portaudio')
endif

common_src = ['src/callbacks.c']
common_deps = [compiler.find_library('opus')]
if host_machine.system() == 'windows'
    ws2_32 = compiler.find_library('ws2_32')
    lib_deps += ws2_32
    common_deps += ws2_32
endif

lib = library(
    'ongaku',
    sources: lib_src,
    dependencies: lib_deps,
    install: true,
)
common_libs = [lib]

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
