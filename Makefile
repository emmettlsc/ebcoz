# Enable eBPF by default (set to 0 to disable)
USE_EBPF ?= 1

# Export to sub-makes
export USE_EBPF

# dirs
EBPF_DIR := src/ebpf
LOADER_DIR := src/loader
PROFILER_DIR := src/profiler
BUILD_DIR := build

# profiler dirs (from BCOZ)
ROOT := $(PROFILER_DIR)
DIRS := libcoz viewer

.PHONY: all clean distclean ebpf loader profiler install check bench bench_small bench_large test help

# default target
all: setup
ifeq ($(USE_EBPF),1)
	@$(MAKE) ebpf
	@$(MAKE) loader
endif
	@$(MAKE) profiler

# make build dir
setup:
	@mkdir -p $(BUILD_DIR)

# build ebpf (bpf + skeleton)
ebpf:
	@echo "Building eBPF program..."
	@$(MAKE) -C $(EBPF_DIR)

# build loader
loader:
	@echo "Building eBPF loader..."
	@$(MAKE) -C $(LOADER_DIR)

# build profiler (BCOZ)
profiler:
	@echo "Building eBCOZ profiler..."
	@$(MAKE) -C $(PROFILER_DIR)
	@echo "Copying executables to build directory..."
	@if [ -f $(PROFILER_DIR)/libcoz/libcoz.so ]; then \
		mkdir -p $(BUILD_DIR)/libcoz; \
		cp $(PROFILER_DIR)/libcoz/libcoz.so $(BUILD_DIR)/libcoz/; \
		echo "Copied libcoz.so"; \
	fi
	@if [ -f $(PROFILER_DIR)/bcoz ]; then \
		cp $(PROFILER_DIR)/bcoz $(BUILD_DIR)/ebcoz; \
		echo "Copied eBCOZ binary"; \
	fi

# install
install::
	@$(MAKE) -C $(PROFILER_DIR) install

# benchmarks
bench bench_small bench_large::
	@$(MAKE) -C $(PROFILER_DIR) $@

# tests
check::
	@$(MAKE) -C $(PROFILER_DIR) check

test: all
ifeq ($(USE_EBPF),1)
	@echo "Running eBPF loader test (requires root)..."
	@if [ -f $(BUILD_DIR)/loader_test ]; then \
		sudo $(BUILD_DIR)/loader_test; \
	else \
		echo "loader_test not found. Run 'make loader' first."; \
	fi
else
	@echo "eBPF is disabled. No eBPF tests to run."
endif

# clean
clean:
ifeq ($(USE_EBPF),1)
	@$(MAKE) -C $(EBPF_DIR) clean
	@$(MAKE) -C $(LOADER_DIR) clean
endif
	@$(MAKE) -C $(PROFILER_DIR) clean
	@rm -rf $(BUILD_DIR)

# deep clean (includes generated headers)
distclean: clean
ifeq ($(USE_EBPF),1)
	@$(MAKE) -C $(EBPF_DIR) distclean
endif
	@$(MAKE) -C $(PROFILER_DIR) distclean

# help
help:
	@echo "eBCOZ Build System"
	@echo ""
	@echo "Usage:"
	@echo "  make [all]       - Build eBCOZ profiler (default)"
	@echo "  make USE_EBPF=0  - Build without eBPF support"
	@echo "  make clean       - Remove build artifacts"
	@echo "  make distclean   - Remove all generated files"
	@echo "  make test        - Run tests (requires root for eBPF)"
	@echo "  make install     - Install to system"
	@echo ""
	@echo "Requirements (with eBPF):"
	@echo "  - clang/llvm (for BPF compilation)"
	@echo "  - bpftool (for skeleton generation)"
	@echo "  - libbpf-dev"
	@echo "  - linux-headers (kernel >= 5.3 with BTF support)"
	@echo ""
	@echo "Current configuration:"
	@echo "  USE_EBPF = $(USE_EBPF)"
