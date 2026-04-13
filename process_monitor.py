#!/usr/bin/python3
from bcc import BPF

# 1. The eBPF C Code (Kernel Space)
bpf_source = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// Define a C struct to hold our data
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};

// Define an eBPF perf ring buffer to send data to user space
BPF_PERF_OUTPUT(events);

// This function will be attached to the sys_clone (fork) system call
int trace_process_creation(struct pt_regs *ctx) {
    struct data_t data = {};

    // Get the process ID of the process making the syscall
    data.pid = bpf_get_current_pid_tgid() >> 32;
    
    // Get the current timestamp
    data.ts = bpf_ktime_get_ns();
    
    // Get the command name (executable name)
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Submit the data to the ring buffer
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

# 2. The Loader (User Space)
print("Compiling eBPF program... (Requires root)")
b = BPF(text=bpf_source)

# Attach the eBPF function to the kernel's clone system call (process creation)
# Note: On newer kernels, the syscall might be clone3 or execve depending on what you want to catch.
syscall = b.get_syscall_fnname("clone")
b.attach_kprobe(event=syscall, fn_name="trace_process_creation")

print("Successfully attached! Tracing new processes... Press Ctrl+C to exit.")
print(f"{'PID':<10} {'COMMAND':<20} {'TIME (ns)'}")

# 3. Handle incoming data from the kernel
def print_event(cpu, data, size):
    # Cast the raw bytes back into our Python-equivalent struct
    event = b["events"].event(data)
    print(f"{event.pid:<10} {event.comm.decode('utf-8', 'replace'):<20} {event.ts}")

# Loop and listen to the ring buffer
b["events"].open_perf_buffer(print_event)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nExiting...")
        exit()
