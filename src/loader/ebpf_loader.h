#ifndef EBPF_LOADER_H
#define EBPF_LOADER_H

#include "../ebpf/blocked_samples.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ebpf_collector;

/* alloc + initialize a heap collector */
struct ebpf_collector *ebpf_collector_create(void);

/* stop + free a heap collector */
void ebpf_collector_destroy(struct ebpf_collector *collector);

/*
 * callback type for processing blocked events
 * @param evt: blocked event from kernel
 * @param ctx: user-provided context
 */
typedef void (*blocked_event_callback_t)(struct blocked_event *evt, void *ctx);

/*
 * init the eBPF collector
 * returns 0 on success, -1 on error
 */
int ebpf_collector_init(struct ebpf_collector *collector);

/*
 * start collecting blocked samples
 * returns 0 on success, -1 on error
 */
int ebpf_collector_start(struct ebpf_collector *collector);

/*
 * poll for events and invoke callback
 * @param callback: func to call for each event
 * @param callback_ctx: context passed to callback
 */
void ebpf_collector_poll(struct ebpf_collector *collector,
                         blocked_event_callback_t callback,
                         void *callback_ctx);

/*
 * stop collection and cleanup
 */
void ebpf_collector_stop(struct ebpf_collector *collector);

/*
 * add a PID to the target filter (only track this process)
 * @param pid: process ID to track
 * returns 0 on success, -1 on error
 */
int ebpf_collector_add_pid(struct ebpf_collector *collector, unsigned int pid);

#ifdef __cplusplus
}
#endif

#endif /* EBPF_LOADER_H */
