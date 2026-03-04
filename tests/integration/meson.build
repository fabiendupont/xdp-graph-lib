# SPDX-License-Identifier: BSD-2-Clause

# Compile TC dummy program for type-rejection testing (FM-NODE-02)
if clang.found()
    tc_dummy_bpf = custom_target('tc_dummy.bpf.o',
        input: 'tc_dummy.bpf.c',
        output: 'tc_dummy.bpf.o',
        command: [clang, bpf_cflags, '-c', '@INPUT@', '-o', '@OUTPUT@'],
        build_by_default: true)
endif

test_pipeline = executable('test_pipeline',
    'test_pipeline.c',
    link_with: xgl_lib,
    include_directories: xgl_inc,
    dependencies: [egl_dep, libbpf_dep, libelf_dep],
    c_args: extra_c_args + ['-DBPF_OBJ_DIR="' + meson.project_build_root() + '"'])

test('test_pipeline', test_pipeline, suite: 'integration',
     is_parallel: false)

test_privileged = executable('test_privileged',
    'test_privileged.c',
    link_with: xgl_lib,
    include_directories: xgl_inc,
    dependencies: [egl_dep, libbpf_dep, libelf_dep],
    c_args: extra_c_args + ['-DBPF_OBJ_DIR="' + meson.project_build_root() + '"'])

test('test_privileged', test_privileged, suite: 'integration',
     is_parallel: false)

test_xsk_privileged = executable('test_xsk_privileged',
    'test_xsk_privileged.c',
    link_with: xgl_lib,
    include_directories: xgl_inc,
    dependencies: [egl_dep, libbpf_dep, libelf_dep],
    c_args: extra_c_args)

test('test_xsk_privileged', test_xsk_privileged, suite: 'integration',
     is_parallel: false)

test_fmea = executable('test_fmea_mitigations',
    'test_fmea_mitigations.c',
    link_with: xgl_lib,
    include_directories: xgl_inc,
    dependencies: [egl_dep, libbpf_dep, libelf_dep],
    c_args: extra_c_args + ['-DBPF_OBJ_DIR="' + meson.project_build_root() + '"'])

test('test_fmea_mitigations', test_fmea, suite: 'integration',
     is_parallel: false)
