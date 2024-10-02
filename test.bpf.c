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

SEC("kprobe/__x64_sys_getpid")
int BPF_KPROBE(do_sys_getpid)
{
    u32 index = 0;
    pid_t *monitoring_pid_ptr = bpf_map_lookup_elem(&my_pid_map, &index);
    pid_t m_pid = monitoring_pid_ptr ? *monitoring_pid_ptr : -1;
    pid_t pid = (pid_t)(bpf_get_current_pid_tgid() >> 32);

    const char fmt[] = "do_sys_getpid called: pid: %d, m_pid: %d\n";
    bpf_trace_printk(fmt, sizeof(fmt), pid, m_pid);

    return 0;
}
