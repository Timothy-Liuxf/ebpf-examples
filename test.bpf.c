#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(do_sys_openat2, int dfd, const char *filename)
{
    const char fmt[] = "do_sys_open: hhhhhhhhhhhhhhhhh name=%s\n";
    bpf_trace_printk(fmt, sizeof(fmt), filename);
    return 0;
}
