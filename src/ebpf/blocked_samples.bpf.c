#include "vmlinux.h"

typedef unsigned long long __u64;
typedef unsigned int __u32;
typedef long long __s64;
typedef int __s32;

#include "blocked_samples.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define PERF_MAX_STACK_DEPTH 127

// sched-out timestamps by tid
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, __u32);   // TID
  __type(value, __u64); // sched-out timestamp (ns)
} block_start SEC(".maps");

// block class map
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, __u32);  // TID
  __type(value, __u8); // block type (IOWAIT/LOCKWAIT/SCHED/UNKNOWN)
} block_reason SEC(".maps");

// user stack map
struct {
  __uint(type, BPF_MAP_TYPE_STACK_TRACE);
  __uint(max_entries, 4096);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(__u64));
} stacks SEC(".maps");

// perf array for events
struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// pid filter (tgid)
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32);   // PID
  __type(value, __u8);  // 1 if we should track
} target_pids SEC(".maps");

/*
 * Classify why a thread was scheduled out
 * Matches BCOZ kernel patch logic in kernel/sched/core.c
 */
static __always_inline __u8 classify_block_reason(struct task_struct *prev,
                                                  unsigned int prev_state) {
  // runnable -> preempt
  if (prev_state == 0)
    return BLOCKED_SCHED;

  // TODO: in_iowait via CO-RE

  // TASK_UNINTERRUPTIBLE (2) often indicates lock/I/O wait
  if (prev_state == 2)
    return BLOCKED_LOCKWAIT; // heuristic

  // TASK_INTERRUPTIBLE (1) could be many things
  if (prev_state == 1)
    return BLOCKED_UNKNOWN;

  return BLOCKED_UNKNOWN;
}

/*
 * Tracepoint: sched/sched_switch
 * Fired on every context switch
 * Format: /sys/kernel/debug/tracing/events/sched/sched_switch/format
 */
SEC("tp/sched/sched_switch")
int trace_sched_switch(struct trace_event_raw_sched_switch *ctx) {
  // prev_pid/next_pid are TIDs
  __u32 prev_tid = ctx->prev_pid;
  __u32 next_tid = ctx->next_pid;

  // tgid for filtering
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid >> 32;  // Upper 32 bits = PID (TGID)

  // only track filtered pids
  if (!bpf_map_lookup_elem(&target_pids, &pid)) {
    return 0;  // Not a target process, skip
  }

  __u64 ts = bpf_ktime_get_ns();

  // sched out
  if (prev_tid != 0) {
    // record sched-out time
    bpf_map_update_elem(&block_start, &prev_tid, &ts, BPF_ANY);

    // classify reason
    struct task_struct *prev = (struct task_struct *)bpf_get_current_task();
    __u8 reason = classify_block_reason(prev, ctx->prev_state);
    bpf_map_update_elem(&block_reason, &prev_tid, &reason, BPF_ANY);
  }

  // sched in
  if (next_tid != 0) {
    __u64 *start_ts = bpf_map_lookup_elem(&block_start, &next_tid);
    if (!start_ts)
      return 0; // No previous sched-out recorded

    __u64 duration = ts - *start_ts;

    // ignore tiny blocks
    if (duration < 1000)
      goto cleanup;

    // build event
    struct blocked_event event = {0};
    event.tid = next_tid;
    event.pid = next_tid; // FIXME: use tgid
    event.duration_ns = duration;
    event.timestamp = ts;

    // block type
    __u8 *reason = bpf_map_lookup_elem(&block_reason, &next_tid);
    event.blocked_type = reason ? *reason : BLOCKED_UNKNOWN;

    // stack capture disabled (overhead)
    event.stack_id = -1;
    // event.stack_id =
    //     bpf_get_stackid(ctx, &stacks, BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP);

    // comm
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // emit
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
                          sizeof(event));

  cleanup:
    // cleanup
    bpf_map_delete_elem(&block_start, &next_tid);
    bpf_map_delete_elem(&block_reason, &next_tid);
  }

  return 0;
}
