#include "../../build/blocked_samples.skel.h"
#include "../ebpf/blocked_samples.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// event callback
typedef void (*blocked_event_callback_t)(struct blocked_event *evt, void *ctx);

struct ebpf_collector {
  struct blocked_samples_bpf *skel;
  struct perf_buffer *pb;
  blocked_event_callback_t callback;
  void *callback_ctx;
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  if (level == LIBBPF_DEBUG)
    return 0;
  return vfprintf(stderr, format, args);
}

// init collector
int ebpf_collector_init(struct ebpf_collector *collector) {
  int err;

  // libbpf logging
  libbpf_set_print(libbpf_print_fn);

  // open/load bpf
  collector->skel = blocked_samples_bpf__open();
  if (!collector->skel) {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    return -1;
  }

  // load/verify
  err = blocked_samples_bpf__load(collector->skel);
  if (err) {
    fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
    blocked_samples_bpf__destroy(collector->skel);
    return -1;
  }

  fprintf(stderr, "[eBPF] Collector initialized successfully\n");
  return 0;
}

// perf buffer sample
static void handle_event(void *ctx, int cpu, void *data, __u32 size) {
  struct ebpf_collector *collector = ctx;
  struct blocked_event *evt = data;

  if (collector->callback) {
    collector->callback(evt, collector->callback_ctx);
  }
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt) {
  fprintf(stderr, "[eBPF] Lost %llu events on CPU %d\n", lost_cnt, cpu);
}

// attach + start
int ebpf_collector_start(struct ebpf_collector *collector) {
  int err;

  // attach sched_switch
  err = blocked_samples_bpf__attach(collector->skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
    return -1;
  }

  // perf buffer
  struct perf_buffer_opts pb_opts = {
      .sample_cb = handle_event,
      .lost_cb = handle_lost_events,
      .ctx = collector,
  };

  collector->pb = perf_buffer__new(bpf_map__fd(collector->skel->maps.events),
                                   8, // 8 pages per CPU
                                   &pb_opts);

  if (!collector->pb) {
    fprintf(stderr, "Failed to create perf buffer\n");
    return -1;
  }

  if (!collector->pb) {
    err = -errno;
    fprintf(stderr, "Failed to create perf buffer: %d\n", err);
    return err;
  }

  fprintf(stderr, "[eBPF] Collector started, attached to sched:sched_switch\n");
  return 0;
}

/*
 * Poll for blocked events and invoke callback
 * This should be called in a loop from the profiler
 */
void ebpf_collector_poll(struct ebpf_collector *collector,
                         blocked_event_callback_t callback,
                         void *callback_ctx) {
  if (!collector->pb) {
    return; // not started yet
  }

  collector->callback = callback;
  collector->callback_ctx = callback_ctx;

  // poll with 100ms timeout
  int err = perf_buffer__poll(collector->pb, 100);
  if (err < 0 && err != -EINTR) {
    fprintf(stderr, "[eBPF] Error polling perf buffer: %d\n", err);
  }
}

// add pid to filter
int ebpf_collector_add_pid(struct ebpf_collector *collector, unsigned int pid) {
  if (!collector || !collector->skel) {
    return -1;
  }

  // insert pid
  __u8 value = 1;  // val doesn't matter, just presence
  int map_fd = bpf_map__fd(collector->skel->maps.target_pids);

  int err = bpf_map_update_elem(map_fd, &pid, &value, BPF_ANY);
  if (err) {
    fprintf(stderr, "[eBPF] Failed to add PID %u to filter: %d\n", pid, err);
    return -1;
  }

  fprintf(stderr, "[eBPF] Added PID %u to filter\n", pid);
  return 0;
}

// stop/detach
void ebpf_collector_stop(struct ebpf_collector *collector) {
  if (collector->pb) {
    perf_buffer__free(collector->pb);
    collector->pb = NULL;
  }

  if (collector->skel) {
    blocked_samples_bpf__destroy(collector->skel);
    collector->skel = NULL;
  }

  fprintf(stderr, "[eBPF] Collector stopped\n");
}

struct ebpf_collector *ebpf_collector_create(void) {
  struct ebpf_collector *collector = calloc(1, sizeof(*collector));
  if (!collector)
    return NULL;

  if (ebpf_collector_init(collector) != 0) {
    free(collector);
    return NULL;
  }
  return collector;
}

void ebpf_collector_destroy(struct ebpf_collector *collector) {
  if (!collector)
    return;

  ebpf_collector_stop(collector);
  free(collector);
}

/*
 * If you want to check that the loader is workign
 */
#ifdef TEST_LOADER
static volatile int stop_flag = 0;

static void sig_handler(int sig) { stop_flag = 1; }

static void test_callback(struct blocked_event *evt, void *ctx) {
  const char *type_str[] = {"NONE", "UNKNOWN", "IOWAIT", "SCHED", "LOCKWAIT"};

  printf("[%s] tid=%u blocked for %llu us (type=%s stack_id=%lld)\n", evt->comm,
         evt->tid, evt->duration_ns / 1000,
         evt->blocked_type < 5 ? type_str[evt->blocked_type] : "?",
         evt->stack_id);
}

int main(int argc, char **argv) {
  struct ebpf_collector collector = {0};

  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  fprintf(stderr, "Initializing eBPF collector...\n");
  if (ebpf_collector_init(&collector) != 0) {
    fprintf(stderr, "Failed to initialize collector\n");
    return 1;
  }

  fprintf(stderr, "Starting eBPF collector...\n");
  if (ebpf_collector_start(&collector) != 0) {
    fprintf(stderr, "Failed to start collector\n");
    ebpf_collector_stop(&collector);
    return 1;
  }

  printf("=== Collecting blocked samples (Ctrl-C to stop) ===\n");

  // Poll loop
  int poll_count = 0;
  while (!stop_flag) {
    ebpf_collector_poll(&collector, test_callback, NULL);

    if (++poll_count % 10 == 0) {
      fprintf(stderr, ".");
      fflush(stderr);
    }
  }

  printf("\n=== Stopping collector ===\n");
  ebpf_collector_stop(&collector);
  return 0;
}
#endif
