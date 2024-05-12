app_src = ['src/callbacks.c']
app_deps = [opus]
if host_machine.system() == 'windows'
    app_deps += cc.find_library('ws2_32')
elif host_machine.system() == 'linux'
    app_deps += cc.find_library('pulse', required: true)
endif
app_libs = [core, crypto, audio]
app_includes = [
    util_include,
    core_include,
    crypto_include,
    audio_include,
    include_directories('include'),
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