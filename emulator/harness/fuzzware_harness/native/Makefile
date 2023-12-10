OWN_DIR := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
UC_DIRNAME := fuzzware-unicorn

LIBDIR = $(OWN_DIR)/../../../unicorn/$(UC_DIRNAME)/
INC=-I$(OWN_DIR)/../../../unicorn/$(UC_DIRNAME)/include
BIN_EXT = .so

CC = clang
CFLAGS += -fpic -Wall -Werror $(INC) -g -O3
LDFLAGS += -shared -L$(LIBDIR) -lunicorn

.PHONY: all clean

SOURCES = native_hooks.c timer.c interrupt_triggers.c util.c state_snapshotting.c native_tracing.c uc_snapshot.c arch_specifics.c
SOURCES += core_peripherals/cortexm/cortexm_nvic.c core_peripherals/cortexm/cortexm_systick.c
SOURCES += core_peripherals/mips/pic32mz_nvic.c core_peripherals/interrupt_common.c


BINS = $(SOURCES:.c=$(BIN_EXT))
OBJS = $(SOURCES:.c=.o)

native_hooks.so: $(OBJS)
	$(CC) $^ $(LDFLAGS) -o $@

all: native_hooks.so

clean:
	rm -rf *.o core_peripherals/*.o core_peripherals/cortexm/*.o core_peripherals/mips/*.o $(BINS)
