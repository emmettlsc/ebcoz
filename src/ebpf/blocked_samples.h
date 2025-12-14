#ifndef BLOCKED_SAMPLES_H
#define BLOCKED_SAMPLES_H

// Block classification types (yoinked from BCOZ)
#define BLOCKED_UNKNOWN    1
#define BLOCKED_IOWAIT     2
#define BLOCKED_SCHED      3   // Preemption
#define BLOCKED_LOCKWAIT   4   // futex/mutex <- which we don't do anything with rn...

// event structure sent from kernel to userspace
struct blocked_event {
    __u32 pid;
    __u32 tid;
    __u64 duration_ns;      // Time blocked
    __u8  blocked_type;     // IOWAIT/LOCKWAIT/SCHED/UNKNOWN
    __u64 timestamp;        // When unblocked
    __s64 stack_id;         // Stack trace ID (from BPF stack map) <- not in use rn, was causing slowdowns (i think)
    char  comm[16];         // Process name
};

#endif /* BLOCKED_SAMPLES_H */
