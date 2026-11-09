# SPDX-License-Identifier: BSD-2-Clause

xgl_check_exe = executable('xgl_check',
    'xgl_check.c',
    link_with: xgl_lib,
    include_directories: xgl_inc,
    dependencies: [egl_dep, libbpf_dep, libelf_dep],
    c_args: extra_c_args,
    install: true)
