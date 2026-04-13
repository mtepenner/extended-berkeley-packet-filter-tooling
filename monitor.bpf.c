//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Define our data structure
struct event {
    __u32 pid;
    __u32 uid;
    __u8  comm[16];
};

// Define a modern BPF RingBuffer to send data to user-space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB buffer
} events SEC(".maps");

// Attach to the execve tracepoint (process execution)
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(void *ctx) {
    struct event *e;

    // Reserve space in the ringbuffer
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0; // Buffer full, drop the event
    }

    // Gather process data
    __u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;                     // Top 32 bits are the PID
    e->uid = bpf_get_current_uid_gid();    // Bottom 32 bits are the UID
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Submit the data to user-space
    bpf_ringbuf_submit(e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
