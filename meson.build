project('ongaku', 'c')
cc = meson.get_compiler('c')

opus = cc.find_library('opus')
if host_machine.system() == 'windows'
    ws2_32 = cc.find_library('ws2_32')
endif

subdir('util')
subdir('core')
subdir('crypto')
subdir('audio')
subdir('app')