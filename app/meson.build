app_src = ['src/callbacks.c', 'src/ioutil.c']
app_deps = [opus]
if host_machine.system() == 'windows'
    app_deps += ws2_32
endif
app_libs = [core, crypto, audio]
app_include = include_directories('include')
app_includes = [
    util_include,
    core_include,
    crypto_include,
    audio_include,
    app_include,
]

executable(
    'ongaku-server',
    sources: app_src + 'src/server.c',
    dependencies: app_deps,
    link_with: app_libs,
    include_directories: app_includes,
    install: true,
)

executable(
    'ongaku-client',
    sources: app_src + 'src/client.c',
    dependencies: app_deps,
    link_with: app_libs,
    include_directories: app_includes,
    install: true,
)

subdir('tests')