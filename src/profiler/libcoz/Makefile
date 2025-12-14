# libcoz Makefile
# Modified for eBCOZ to support eBPF integration

ROOT := ..
TARGETS := libcoz.so

# Standard libraries
LIBS := -ldl -lrt -lpthread -Wl,--no-as-needed -ldl \
        -Wl,--rpath=/usr/local/lib/glibc-testing-2.30/lib \
        -Wl,--dynamic-linker=/trusted/local/lib/glibc-testing-2.30/lib/ld-linux.so.2 \
        $(shell pkg-config --libs libelf++ libdwarf++)

# Add eBPF libraries if enabled
ifeq ($(USE_EBPF),1)
LIBS += -lbpf -lelf
endif

# Standard C++ flags
CXXFLAGS := -gdwarf-3 --std=c++0x -g -O2 -fno-omit-frame-pointer -fPIC \
            -I$(ROOT)/include -I. \
            $(shell pkg-config --cflags libelf++ libdwarf++)

# Add eBPF includes and define if enabled
ifeq ($(USE_EBPF),1)
CXXFLAGS += -DUSE_EBPF -I../../../build -I../../../src/loader -I../../../src/ebpf
endif

# Additional objects to link
EXTRA_OBJS :=
ifeq ($(USE_EBPF),1)
EXTRA_OBJS += ../../../build/ebpf_loader.o
endif

include $(ROOT)/common.mk

# Override linking rule to include extra objects
libcoz.so: $(OBJS) $(EXTRA_OBJS)
	@echo $(LOG_PREFIX) Linking $@ $(LOG_SUFFIX)
	@$(CXX) -shared $(LDFLAGS) -o $@ $(OBJS) $(EXTRA_OBJS) $(LIBS)

check:: libcoz.so
	printf "int main(int argc, char *argv[])\n{\nreturn (0);\n}\n" > x.c
	gcc -g -o x x.c || ( $(RM) x x.c ; exit 1)
	../coz run --- ./x
	if grep -q time= profile.coz; then echo success: coz profiler ran as it should.; fi
	$(RM) -f x.c x profile.coz
