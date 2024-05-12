sodium = cc.find_library('sodium')

crypto_src = [
    'src/plaintext.c',
    'src/sodium.c',
]
crypto_deps = [sodium]
crypto_include = include_directories('include')
crypto_includes = [util_include, crypto_include]

crypto = library(
    'ongakucrypto',
    sources: crypto_src,
    dependencies: crypto_deps,
    include_directories: crypto_includes,
    install: true,
)

subdir('tests')