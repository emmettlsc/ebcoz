# eBCOZ: Cross-Layer Causal Profiler

eBCOZ extends BCOZ’s causal profiling to async workloads while removing the patched-kernel dependency.

## Status
- eBPF integration is wired into the profiler; blocked samples flow via sched_switch. Block classification still needs CO-RE reads for IOWAIT/futex, ... and user stacks are currently disabled to avoid stalls

## Layout
```
src/ebpf/          # BPF program and maps
src/loader/        # loader for userspace + perf_buffer polling
src/profiler/      # the BCOZ-derived profiler that was minimally changed
benchmarks/        # synthetic workloads
build/             # build artifacts (not tracked)
```

## Quick Run
```bash
# Install deps, then in project root dir:
make all               # eBPF on by default

# Compile some program with COZ macros:
g++ <file>.cpp -O2 -g -gdwarf-4 -fno-omit-frame-pointer -DCOZ_PROFILING -I../../src/profiler/include -ldl -pthread

# Run with eBCOZ: 
sudo ./build/ebcoz run --- ./<executable>
```


## System Requirements
```
sudo apt-get install clang llvm libbpf-dev linux-headers-\$(uname -r) linux-tools-common

```