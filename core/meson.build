core_src = [
    'src/log.c',
    'src/pool.c',
    'src/protocol.c',
    'src/ringbuf.c',
    'src/socket.c',
]
core_deps = []
if host_machine.system() == 'windows'
    core_deps += ws2_32
endif
core_include = include_directories('include')
core_includes = [util_include, core_include]

core = library(
    'ongakucore',
    sources: core_src,
    dependencies: core_deps,
    include_directories: core_includes,
    install: true,
)

subdir('tests')