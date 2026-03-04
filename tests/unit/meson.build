# SPDX-License-Identifier: BSD-2-Clause

test_meta = executable('test_meta',
    'test_meta.c',
    include_directories: xgl_inc,
    c_args: extra_c_args)

test('test_meta', test_meta, suite: 'unit')

test_meta_get = executable('test_meta_get',
    'test_meta_get.c',
    include_directories: xgl_inc,
    c_args: extra_c_args)

test('test_meta_get', test_meta_get, suite: 'unit')

test_xsk = executable('test_xsk',
    'test_xsk.c',
    link_with: xgl_lib,
    include_directories: xgl_inc,
    dependencies: [egl_dep, libbpf_dep, libelf_dep],
    c_args: extra_c_args)

test('test_xsk', test_xsk, suite: 'unit')

test_wrapper = executable('test_wrapper',
    'test_wrapper.c',
    link_with: xgl_lib,
    include_directories: xgl_inc,
    dependencies: [egl_dep, libbpf_dep, libelf_dep],
    c_args: extra_c_args)

test('test_wrapper', test_wrapper, suite: 'unit')
