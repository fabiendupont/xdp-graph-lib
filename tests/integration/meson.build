# SPDX-License-Identifier: BSD-2-Clause

# Compile TC dummy program for type-rejection testing (FM-NODE-02)
# and edge-metadata test nodes (XGL_EDGE declarations).
if clang.found()
    tc_dummy_bpf = custom_target('tc_dummy.bpf.o',
        input: 'tc_dummy.bpf.c',
        output: 'tc_dummy.bpf.o',
        command: [clang, bpf_cflags, '-c', '@INPUT@', '-o', '@OUTPUT@'],
        build_by_default: true)

    edge_node_a_bpf = custom_target('edge_node_a.bpf.o',
        input: '../bpf/edge_node_a.bpf.c',
        output: 'edge_node_a.bpf.o',
        command: [clang, bpf_cflags, '-c', '@INPUT@', '-o', '@OUTPUT@'],
        build_by_default: true)

    edge_node_b_bpf = custom_target('edge_node_b.bpf.o',
        input: '../bpf/edge_node_b.bpf.c',
        output: 'edge_node_b.bpf.o',
        command: [clang, bpf_cflags, '-c', '@INPUT@', '-o', '@OUTPUT@'],
        build_by_default: true)
endif

test_edge_ingest = executable('test_edge_ingest',
    'test_edge_ingest.c',
    link_with: xgl_lib,
    include_directories: xgl_inc,
    dependencies: [egl_dep, libbpf_dep, libelf_dep],
    c_args: extra_c_args + ['-DEDGE_OBJ_DIR="' + meson.project_build_root() + '/tests/integration"'])

test('test_edge_ingest', test_edge_ingest, suite: 'integration',
     is_parallel: false)

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
    c_args: extra_c_args + ['-DBPF_OBJ_DIR="' + meson.project_build_root() + '"'])

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
