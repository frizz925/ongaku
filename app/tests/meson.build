test_deps = []
if host_machine.system() == 'windows'
    test_deps += ws2_32
endif
test_libs = [crypto]
test_includes = [util_include, crypto_include, app_include]

test(
    'app/ioutil test',
    executable(
        'ioutil_test',
        sources: ['../src/ioutil.c', 'ioutil_test.c'],
        dependencies: test_deps,
        link_with: test_libs,
        include_directories: test_includes,
    ),
)