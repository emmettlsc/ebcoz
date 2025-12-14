# build userspace loader and test

# compiler
CC ?= gcc

# build dir (relative to project root)
BUILD_DIR := ../../build

# include dirs
INCLUDES := -I. -I../ebpf -I$(BUILD_DIR)

# source/objects
LOADER_SRC := ebpf_loader.c
LOADER_OBJ := $(BUILD_DIR)/ebpf_loader.o

# test binary
LOADER_TEST := $(BUILD_DIR)/loader_test

# cflags
CFLAGS := -O2 -Wall -fPIC $(INCLUDES)

# ldflags for test
LDFLAGS := -lbpf -lelf -lpthread

.PHONY: all clean test

# default target
all: $(LOADER_OBJ)

# build loader object (linked into libcoz)
$(LOADER_OBJ): $(LOADER_SRC) ebpf_loader.h $(BUILD_DIR)/blocked_samples.skel.h
	@mkdir -p $(BUILD_DIR)
	@echo "  [CC] Compiling eBPF loader..."
	@$(CC) $(CFLAGS) -c $(LOADER_SRC) -o $@

# build standalone test
$(LOADER_TEST): $(LOADER_SRC) ebpf_loader.h $(BUILD_DIR)/blocked_samples.skel.h
	@mkdir -p $(BUILD_DIR)
	@echo "  [CC] Building loader test..."
	@$(CC) $(CFLAGS) -DTEST_LOADER $(LOADER_SRC) -o $@ $(LDFLAGS)

# test target
test: $(LOADER_TEST)

# clean
clean:
	@rm -f $(LOADER_OBJ) $(LOADER_TEST)
