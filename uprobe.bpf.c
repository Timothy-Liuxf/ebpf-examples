#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, pid_t);
} my_pid_map SEC(".maps");

SEC("uprobe//home/timothy/code/codes/ebpf/ebpf-examples/a.out:add")
int BPF_UPROBE(add, int x, int y)
{
    (void)x;
    (void)y;

    u32 index = 0;
    pid_t *monitoring_pid_ptr = bpf_map_lookup_elem(&my_pid_map, &index);
    pid_t m_pid = monitoring_pid_ptr ? *monitoring_pid_ptr : -1;
    pid_t pid = (pid_t)(bpf_get_current_pid_tgid() >> 32);

    const char fmt[] = "uprobe: user function add called: pid: %d, m_pid: %d\n";
    bpf_trace_printk(fmt, sizeof(fmt), pid, m_pid);

    return 0;
}
