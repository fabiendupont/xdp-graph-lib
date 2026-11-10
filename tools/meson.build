# SPDX-License-Identifier: BSD-2-Clause

xgl_check_exe = executable('xgl_check',
    'xgl_check.c',
    link_with: xgl_lib,
    include_directories: xgl_inc,
    dependencies: [egl_dep, libbpf_dep, libelf_dep],
    c_args: extra_c_args,
    install: true)

xgl_edges_exe = executable('xgl_edges',
    'xgl_edges.c',
    link_with: xgl_lib,
    include_directories: xgl_inc,
    dependencies: [egl_dep, libbpf_dep, libelf_dep],
    c_args: extra_c_args,
    install: true)
