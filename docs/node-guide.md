# Writing XDP Graph Nodes

How to create a BPF node, compile it, load it into an XDP graph,
verify it, and avoid the code shapes that break offline verification.

The full API references are in the headers (`include/xgl/*.h`,
`subprojects/ebpf-graph-lib/include/egl/*.h`); this guide is the
path through them. The `examples/l2fwd/` directory contains a
complete working instance of everything described here.

## The model in one paragraph

An XDP *graph* is a set of BPF programs ("nodes") composed at
runtime via a shared `BPF_MAP_TYPE_PROG_ARRAY`: a node ends by
tail-calling the next node's slot, chosen by a compile-time index
or by `meta->next_node`. One node is the *root* (slot 0): it runs
first on every packet, allocates the shared metadata in the packet
headroom, and tail-calls into the pipeline. The graph is a DAG —
`xgl_graph_validate_dag()` enforces it before attach. Each node
also has a stats row (indexed by its slot number) in a shared
stats map, so every node's RX/TX/drop/error counters are readable
from userspace at any time.

```
                 ┌────────────┐
   packet ──────▶│  dispatch  │ (root, slot 0: XGL_META_ALLOC, stats,
                 └─────┬──────┘  XGL_NEXT into the pipeline)
             ┌────────┼────────┐
             ▼        ▼        ▼
        ┌────────┐┌───────┐┌──────┐
        │ node 1 ││ node 2││ ...  │  (your nodes)
        └────────┘└───────┘└──────┘
```

## Writing a BPF node

### The entry point

```c
#include <xgl/bpf/xgl_common.bpf.h>   /* brings in egl_* + xgl_* maps */

char LICENSE[] SEC("license") = "BSD-3-Clause";

#define MY_NODE_ID 1   /* PROG_ARRAY slot — must match the loader */

XGL_NODE(my_node)
{
    struct xgl_meta *meta = XGL_META_GET(ctx);
    if (!meta) {
        XGL_STATS_INC_ERROR(egl_node_stats, MY_NODE_ID);
        XGL_DROP();
    }
    /* ... */
}
```

`XGL_NODE(name)` expands to `SEC("xdp") int name(struct xdp_md *ctx)`
— the loader finds the program by section and name.

### Reading the packet

Always bounds-check before touching packet data, and compute
lengths in **64-bit**:

```c
void *data     = (void *)(long)ctx->data;
void *data_end = (void *)(long)ctx->data_end;

if (data + sizeof(struct ethhdr) > data_end)
    XGL_DROP();

__u64 pkt_len = data_end - data;      /* NOT (__u32)(data_end - data) */
```

The 64-bit rule is not style — see *Verifiable code shapes* below.
The kernel verifier tolerates 32-bit pointer arithmetic today;
PREVAIL does not, and the kernel's tolerance is not a contract.

### Metadata and scratch

The root node calls `XGL_META_ALLOC(ctx)` once; every other node
reads it with `XGL_META_GET(ctx)` (NULL if the headroom is absent —
always handle it). `struct xgl_meta` (52 bytes, in packet headroom)
carries:

| Field | Meaning |
|---|---|
| `l2_proto`, `l3_offset` | parsed header info |
| `next_node` | next PROG_ARRAY slot (for dynamic dispatch) |
| `ingress_ifindex`, `timestamp_ns` | filled by the root |
| `scratch[32]` | inter-node communication buffer |

Scratch is zero-initialized by the root and has ownership rules
(documented in `xgl_meta.h`): a node must not read a scratch field
no known upstream node writes, and two nodes must not write the
same field unless the topology guarantees they never both run on a
packet. Access it typed:

```c
struct my_scratch { __u16 vlan_id; __u8 port; };
struct my_scratch *s = XGL_SCRATCH_AS(meta, struct my_scratch);
```

`_Static_assert` in the macro rejects types larger than 32 bytes.

### Handing the packet on

```c
/* compile-time next node */
XGL_NEXT(ctx, egl_prog_array, NEXT_NODE_ID);

/* dynamic (from packet data / meta) — bounds-checked */
XGL_NEXT_SAFE(ctx, egl_prog_array, meta->next_node,
              egl_node_stats, MY_NODE_ID);

/* terminal actions */
XGL_DROP();
XGL_PASS();
```

A tail call that *returns* has failed (bad slot, no program);
follow it with a fallback action.

### Stats

`egl_node_stats` is a shared per-node stats map. Every outcome
should be visible:

```c
XGL_STATS_INC_RX(egl_node_stats, MY_NODE_ID, pkt_len); /* entry */
XGL_STATS_INC_TX(egl_node_stats, MY_NODE_ID, pkt_len); /* forwarded */
XGL_STATS_INC_DROP(egl_node_stats, MY_NODE_ID);        /* dropped */
XGL_STATS_INC_ERROR(egl_node_stats, MY_NODE_ID);       /* bad state */
```

The node ID is the PROG_ARRAY slot — keep the two consistent.

## Compiling a node

The flags the library itself uses (a node outside the tree needs
the two include paths):

```sh
clang -target bpf -O2 -g -D__TARGET_ARCH_x86 \
    -I<path-to>/xdp-graph-lib/include \
    -I<path-to>/ebpf-graph-lib/include \
    -c my_node.bpf.c -o my_node.bpf.o
```

Inside a meson project, declare it as a custom target so it lands
in the build dir next to the userspace code (see
`examples/l2fwd/meson.build`):

```meson
node_o = custom_target('my_node.bpf.o',
    input: 'src/bpf/my_node.bpf.c',
    output: 'my_node.bpf.o',
    command: [clang, bpf_cflags, '-c', '@INPUT@', '-o', '@OUTPUT@'],
    build_by_default: true)
```

## Loading the graph from userspace

The full sequence (from `examples/l2fwd/l2fwd_main.c`):

```c
#include <xgl/xgl_graph.h>

struct xgl_graph *g = xgl_graph_create("my-pipeline", 0);
/*                                       ^ max_nodes, 0 = 256 slots */

xgl_graph_add_node(g, 0, "xgl_dispatch.bpf.o", "xgl_dispatch"); /* root */
xgl_graph_add_node(g, 1, "my_node.bpf.o",       "my_node");
xgl_graph_add_node(g, 2, "other_node.bpf.o",    "other_node");

xgl_graph_add_edge(g, 0, 1);   /* declare edges — used by DAG check */
xgl_graph_add_edge(g, 1, 2);

if (xgl_graph_validate_dag(g)) { /* cycles / unreachable nodes */ ... }

xgl_graph_attach(g, "eth0");  /* native mode, skb fallback */
/* ... run ... */
xgl_graph_destroy(g);         /* detaches and cleans up */
```

`xgl_graph_attach()` validates the DAG itself before attaching
(SSR-WRAP-003) and prefers driver (native) XDP, falling back to
generic (skb) mode. It requires `CAP_NET_ADMIN` and `CAP_BPF`.

### Slot allocation

Fixed indices (as above) are fine for a self-contained pipeline.
When multiple projects compose into one interface, use dynamic
allocation to avoid slot collisions:

```c
int idx = egl_graph_alloc_index(g);      /* picks a free slot */
egl_graph_reserve_index(g, FIXED_IDX);   /* or reserve a known one */
egl_graph_free_index(g, idx);            /* on node removal */
```

For cross-project composition (two projects sharing one attached
graph via a pinned PROG_ARRAY), create the graph with
`xgl_graph_create_shared(name, max_nodes, pin_path)` — it joins
the pinned array if it exists, or creates and pins a new one.

### AF_XDP sockets

```c
struct xgl_xsk *xsk = xgl_graph_create_xsk(g, "eth0", queue_id);
```

creates and binds a socket (zero-copy preferred, copy fallback)
and inserts it into the graph's XSKMAP at `queue_id`. See
`xgl_xsk.h` for receive/transmit and the rootless
`xgl_xsk_inherit()` fd-handoff API.

## Verification

A node ships with three gates; all are wired into CI:

1. **CBMC (C source)** — write a harness per node under
   `verification/cbmc/` proving bounds and overflow properties of
   the parsing logic (see `meta_bounds_harness.c` for the shape).
2. **PREVAIL (compiled object)** — run `scripts/prevail-check.sh
   <prevail-binary> <builddir>`; every `.bpf.o` in the build dir is
   verified at the bytecode level, kernel-independently.
   PREVAIL is deliberately *more conservative* than the kernel
   verifier: code the kernel accepts may be rejected. That is the
   point — pass PREVAIL and you are robust to kernel changes.
3. **xgl_check (graph configuration)** — when an orchestrator (e.g.
   the DRA driver) composes graphs from claim parameters, the
   resulting configuration is validated by the `xgl_check` tool
   before anything is loaded: unique slots, DAG, queue dedication,
   disjoint EtherType filter sets. Node authors don't invoke this
   directly, but the invariants it checks (one consumer per queue,
   one path per EtherType) are the contract your node participates
   in.

### Verifiable code shapes

Shapes that load in today's kernel but fail PREVAIL — found the
hard way in this codebase, so none of these are theoretical:

* **32-bit pointer arithmetic.**
  `(__u32)(data_end - data)` makes clang emit `sub32` on packet
  pointers. Always `__u64`. (Caught in five nodes across the
  family.)
* **Hoisted loads across helper calls.** Computing
  `data_end - data` early, then calling a helper (ktime, map
  update) before using the result, makes clang *spill the packet
  pointer* across the call and reload it — the region type is lost.
  Compute lengths at the point of use. (Caught in `l2fwd_rx`.)
* **Casting pointers to integers before subtracting.**
  `(int)((long)data_end - (long)p)` is the same 32-bit trap with
  extra steps. Subtract the pointers, keep the result `__u64`.

The rule of thumb: pointer subtraction happens once, in 64-bit,
adjacent to the loads, at the point of use.

## Checklist for a new node

- [ ] `XGL_NODE` entry, unique program name
- [ ] Slot ID decided (fixed or `egl_graph_alloc_index`) and used
      consistently for stats and tail calls
- [ ] `XGL_META_GET` NULL-handled
- [ ] All packet accesses bounds-checked
- [ ] Lengths computed in 64-bit at point of use
- [ ] Every exit path increments a stats counter
- [ ] Scratch usage documented (read/write fields)
- [ ] `scripts/prevail-check.sh` PASS on the built object
- [ ] CBMC harness for any non-trivial parsing
- [ ] Loader declares edges + `xgl_graph_validate_dag()`
