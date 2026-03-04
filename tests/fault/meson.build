# SPDX-License-Identifier: BSD-2-Clause

# Fault injection shared library (LD_PRELOAD)
libfault_alloc = shared_library('fault_alloc',
    'libfault_alloc.c',
    c_args: ['-fPIC', '-Wno-missing-prototypes'],
    link_args: ['-ldl'],
    override_options: ['werror=false'])

# Fault injection test binary
test_fault_xgl = executable('test_fault_xgl',
    'test_fault_xgl.c',
    link_with: xgl_lib,
    include_directories: xgl_inc,
    dependencies: [egl_dep, libbpf_dep, libelf_dep],
    c_args: extra_c_args)

# Without LD_PRELOAD — baseline sanity check
test('test_fault_xgl', test_fault_xgl, suite: 'fault')
