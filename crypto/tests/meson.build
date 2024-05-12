test(
    'crypto test suites',
    executable(
        'test_suites',
        sources: [
            '../src/plaintext.c',
            '../src/sodium.c',
            'test_suites.c',
        ],
        dependencies: sodium,
        include_directories: crypto_includes,
    ),
)