# xdp-graph-lib

XDP-specific layer on top of [ebpf-graph-lib](../ebpf-graph-lib/),
providing XDP headroom metadata, XDP node macros, XDP interface
attachment, DEVMAP management, and AF_XDP zero-copy socket abstraction.

## Architecture

```
ebpf-graph-lib (egl_*)    ← generic: PROG_ARRAY, DAG, stats, reconfig
└── xdp-graph-lib (xgl_*) ← THIS: XDP metadata, actions, AF_XDP zero-copy, DEVMAP
```

## Features

- **XDP headroom metadata**: 52-byte `xgl_meta` struct in packet headroom
- **XDP node macros**: `XGL_NODE()`, `XGL_META_GET()`, `XGL_META_ALLOC()`
- **XDP actions**: `XGL_DROP()`, `XGL_PASS()`
- **AF_XDP zero-copy**: `xgl_xsk_*` API with `XDP_ZEROCOPY` preferred
- **DEVMAP helpers**: `XGL_DECLARE_DEVMAP()`, `XGL_REDIRECT_MAP()`
- **XSKMAP helpers**: `XGL_DECLARE_XSKMAP()`, `XGL_REDIRECT_XSK()`
- **XDP attachment**: `xgl_graph_attach()` / `xgl_graph_detach()`

## Documentation

- **[Writing XDP graph nodes](docs/node-guide.md)** — create a node,
  compile it, load it into a graph, verify it. Start here.
- [Safety documentation](docs/safety/) — failure-mode analysis,
  verification methodology.

## Building

```sh
meson setup builddir
meson compile -C builddir
meson test -C builddir
```

## Dependencies

- ebpf-graph-lib
- libbpf >= 1.0
- libelf
- clang (BPF compilation)

## License

BSD-3-Clause
