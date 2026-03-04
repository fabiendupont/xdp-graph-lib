/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * Minimal TC BPF program for type-rejection testing.
 * Used by test_fmea_mitigations to verify that xgl_graph_add_node
 * rejects non-XDP programs (FM-NODE-02).
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tc")
int tc_dummy(struct __sk_buff *skb)
{
    (void)skb;
    return 0; /* TC_ACT_OK */
}

char _license[] SEC("license") = "BSD";
