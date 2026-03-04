# SPDX-License-Identifier: BSD-2-Clause

l2fwd_main = executable('l2fwd',
    'l2fwd_main.c',
    link_with: xgl_lib,
    include_directories: xgl_inc,
    dependencies: [egl_dep, libbpf_dep, libelf_dep],
    c_args: extra_c_args)

if clang.found()
    l2fwd_rx_bpf = custom_target('l2fwd_rx.bpf.o',
        input: 'l2fwd_rx.bpf.c',
        output: 'l2fwd_rx.bpf.o',
        command: [clang, bpf_cflags, '-c', '@INPUT@', '-o', '@OUTPUT@'],
        build_by_default: true)

    l2fwd_tx_bpf = custom_target('l2fwd_tx.bpf.o',
        input: 'l2fwd_tx.bpf.c',
        output: 'l2fwd_tx.bpf.o',
        command: [clang, bpf_cflags, '-c', '@INPUT@', '-o', '@OUTPUT@'],
        build_by_default: true)
endif
