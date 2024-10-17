#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("uprobe//usr/bin/python3.12:PyEval_EvalFrame")
int BPF_UPROBE(pyeval, void *f)
{
    (void)f;

    u32 index = 0;
    pid_t pid = (pid_t)(bpf_get_current_pid_tgid() >> 32);

    const char fmt[] = "uprobe: user function PyEval_EvalFrame called: pid: %d\n";
    bpf_trace_printk(fmt, sizeof(fmt), pid);
    return 0;
}

SEC("uprobe//usr/bin/python3.12:PyEval_EvalFrameEx")
int BPF_UPROBE(pyevalex, void *f, int throwflag)
{
    (void)f;
    (void)throwflag;

    u32 index = 0;
    pid_t pid = (pid_t)(bpf_get_current_pid_tgid() >> 32);

    const char fmt[] = "uprobe: user function PyEval_EvalFrameEx called: pid: %d\n";
    bpf_trace_printk(fmt, sizeof(fmt), pid);
    return 0;
}

SEC("uprobe//usr/bin/python3.12:_PyEval_EvalFrameDefault")
int BPF_UPROBE(pyevaldefault, void *tstate, void *frame, int throwflag)
{
    (void)tstate;
    (void)frame;
    (void)throwflag;

    u32 index = 0;
    pid_t pid = (pid_t)(bpf_get_current_pid_tgid() >> 32);

    const char fmt[] = "uprobe: user function _PyEval_EvalFrameDefault called: pid: %d\n";
    bpf_trace_printk(fmt, sizeof(fmt), pid);
    return 0;
}
