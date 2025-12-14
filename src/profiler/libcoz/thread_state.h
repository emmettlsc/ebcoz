/*
 * Copyright (c) 2015, Charlie Curtsinger and Emery Berger,
 *                     University of Massachusetts Amherst
 * This file is part of the Coz project. See LICENSE.md file at the top-level
 * directory of this distribution and at http://github.com/plasma-umass/coz.
 */

#if !defined(CAUSAL_RUNTIME_THREAD_STATE_H)
#define CAUSAL_RUNTIME_THREAD_STATE_H

#include <atomic>
#include <deque>
#include <fstream>
#include <iostream>
#include "ccutil/timer.h"

#include "perf.h"
#ifdef USE_EBPF
#include "../../ebpf/blocked_samples.h"
#endif

class thread_state {
public:
  bool in_use = false;      //< Set by the main thread to prevent signal handler from racing
  size_t based_local_delay = 0;   //< The count of delays (or selected based-line visits) in the thread
  size_t local_delay = 0;   //< The count of delays (or selected line visits) in the thread
  size_t delayed_local_delay = 0;
  perf_event sampler;         //< On-CPU sampler (perf_event) for this thread
#ifdef USE_EBPF
  std::deque<blocked_event> blocked_events; //< Off-CPU blocked samples delivered from eBPF
#endif
  timer process_timer;      //< The timer that triggers sample processing for this thread
  size_t pre_block_time;    //< The time saved before (possibly) blocking
  size_t pre_local_time;
  std::atomic<int> process_samples;
  uint64_t ex_count = 1;
  // separate clocks (perf vs ebpf)
  uint64_t last_perf_time = 0;
#ifdef USE_EBPF
  uint64_t last_ebpf_time = 0;
#endif
  bool in_wait = false;
  bool enable_print_log = false;
  std::atomic<bool> sync_local_with_global;

  std::ofstream fout;

  inline void set_in_use(bool value) {
    in_use = value;
    std::atomic_signal_fence(std::memory_order_seq_cst);
  }
  
  bool check_in_use() {
    return in_use;
  }
};

#endif
