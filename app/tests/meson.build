test_includes = [util_include, crypto_include, app_include]

test(
    'app/ioutil test',
    executable(
        'ioutil_test',
        sources: ['../src/ioutil.c', 'ioutil_test.c'],
        link_with: crypto,
        include_directories: test_includes,
    ),
)