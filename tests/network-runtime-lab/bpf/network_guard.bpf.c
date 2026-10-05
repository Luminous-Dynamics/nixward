// SPDX-License-Identifier: GPL-2.0
// V44 disposable runtime-lab program. This is test code, not production policy.
#include <linux/bpf.h>
#include <linux/types.h>

#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#define bpf_ntohs(x) __builtin_bswap16(x)

static void *(*bpf_map_lookup_elem)(void *map, const void *key) =
    (void *)BPF_FUNC_map_lookup_elem;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;

struct lab_policy {
    __u16 destination_port;
    __u8 mode; /* 0 allow, 1 deny, 2 lease */
    __u8 reserved;
    __u32 generation;
    __u64 lease_expires_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct lab_policy);
} policy SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} active_generation SEC(".maps");

static __always_inline int decide(struct bpf_sock_addr *ctx)
{
    __u32 key = 0;
    struct lab_policy *p = bpf_map_lookup_elem(&policy, &key);
    __u32 *active = bpf_map_lookup_elem(&active_generation, &key);
    if (!p || !active)
        return 0; /* fail closed in the lab */
    if (p->generation == 0 || p->generation != *active)
        return 0; /* stale/incomplete policy generation */

    __u16 port = bpf_ntohs((__u16)ctx->user_port);
    if (p->destination_port != 0 && port != p->destination_port)
        return 1;
    if (p->mode == 0)
        return 1;
    if (p->mode == 1)
        return 0;
    if (p->mode == 2)
        return bpf_ktime_get_ns() < p->lease_expires_ns;
    return 0;
}

SEC("cgroup/connect4")
int symthaea_connect4(struct bpf_sock_addr *ctx) { return decide(ctx); }
SEC("cgroup/connect6")
int symthaea_connect6(struct bpf_sock_addr *ctx) { return decide(ctx); }
SEC("cgroup/sendmsg4")
int symthaea_sendmsg4(struct bpf_sock_addr *ctx) { return decide(ctx); }
SEC("cgroup/sendmsg6")
int symthaea_sendmsg6(struct bpf_sock_addr *ctx) { return decide(ctx); }

char LICENSE[] SEC("license") = "GPL";
