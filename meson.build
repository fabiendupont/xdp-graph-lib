# SPDX-License-Identifier: BSD-2-Clause

project('xdp-graph-lib', 'c',
    version: '0.2.0',
    license: 'BSD-2-Clause',
    meson_version: '>=0.56.0',
    default_options: [
        'c_std=c11',
        'warning_level=3',
        'buildtype=debug',
        'werror=true',
    ])

cc = meson.get_compiler('c')

extra_c_args = cc.get_supported_arguments(
    '-Wconversion', '-Wshadow', '-Wstrict-prototypes', '-Wmissing-prototypes')

# Dependencies
egl_dep = dependency('ebpf-graph-lib',
    fallback: ['ebpf-graph-lib', 'egl_dep'])
libbpf_dep = dependency('libbpf', version: '>=1.0')
libxdp_dep = dependency('libxdp')
libelf_dep = dependency('libelf')

xgl_inc = include_directories('include')
xgl_inc_dir = meson.current_source_dir() / 'include'

# BPF common header — public API for BPF node programs.
# Lives under include/xgl/bpf/ so it resolves via -I<include>.
install_headers('include/xgl/bpf/xgl_common.bpf.h', subdir: 'xgl/bpf')

# BPF compilation via custom_target
clang = find_program('clang', required: false)

# Locate ebpf-graph-lib include dir.  When used as a subproject, meson
# promotes nested subprojects to the top-level subprojects/ directory,
# so we cannot hardcode a relative path.  Use the exported variable.
egl_sub = subproject('ebpf-graph-lib')
egl_inc_dir = egl_sub.get_variable('egl_inc_dir')

bpf_cflags = ['-target', 'bpf', '-O2', '-g', '-Wall', '-Wextra',
              '-D__TARGET_ARCH_x86',
              '-I' + meson.current_source_dir() / 'include',
              '-I' + egl_inc_dir]

if clang.found()
    xgl_dispatch_bpf = custom_target('xgl_dispatch.bpf.o',
        input: 'src/bpf/xgl_dispatch.bpf.c',
        output: 'xgl_dispatch.bpf.o',
        command: [clang, bpf_cflags, '-c', '@INPUT@', '-o', '@OUTPUT@'],
        build_by_default: true)
endif

# Userspace static library (XDP-specific layer only)
xgl_lib = static_library('xgl',
    'src/userspace/xgl_graph.c',
    'src/userspace/xgl_xsk.c',
    'src/userspace/xgl_check.c',
    include_directories: xgl_inc,
    dependencies: [egl_dep, libbpf_dep, libxdp_dep, libelf_dep],
    c_args: extra_c_args)

xgl_dep = declare_dependency(
    link_with: xgl_lib,
    include_directories: xgl_inc,
    dependencies: [egl_dep, libbpf_dep, libxdp_dep])

if get_option('enable_tests')
    subdir('tests')
endif

if get_option('enable_examples')
    subdir('examples')
endif

subdir('tools')

summary({
    'Project': meson.project_name(),
    'Version': meson.project_version(),
    'C Standard': get_option('c_std'),
    'Build Type': get_option('buildtype'),
    'Clang (BPF)': clang.found() ? clang.full_path() : 'not found (BPF targets skipped)',
}, section: 'Configuration')
