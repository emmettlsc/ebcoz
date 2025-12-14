# build bpf program + skeleton

# tools
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool

# build dir (relative to project root)
BUILD_DIR := ../../build

# source/outputs
BPF_SRC := blocked_samples.bpf.c
BPF_OBJ := $(BUILD_DIR)/blocked_samples.bpf.o
BPF_SKEL := $(BUILD_DIR)/blocked_samples.skel.h
VMLINUX_H := vmlinux.h

# bpf cflags
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -I.

.PHONY: all clean distclean

# default
all: $(BPF_SKEL)

# generate vmlinux.h for CO-RE
$(VMLINUX_H):
	@echo "  [BPFTOOL] Generating vmlinux.h..."
	@$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@
	@echo "  Note: If this fails, ensure kernel has BTF support (CONFIG_DEBUG_INFO_BTF=y)"

# build bpf object
$(BPF_OBJ): $(BPF_SRC) $(VMLINUX_H)
	@mkdir -p $(BUILD_DIR)
	@echo "  [CLANG] Compiling BPF program..."
	@$(CLANG) $(BPF_CFLAGS) -c $(BPF_SRC) -o $@
	@$(LLVM_STRIP) -g $@

# gen skeleton header
$(BPF_SKEL): $(BPF_OBJ)
	@echo "  [BPFTOOL] Generating BPF skeleton..."
	@$(BPFTOOL) gen skeleton $< > $@

# clean
clean:
	@rm -f $(BPF_OBJ) $(BPF_SKEL)

# clean + vmlinux.h
distclean: clean
	@rm -f $(VMLINUX_H)
