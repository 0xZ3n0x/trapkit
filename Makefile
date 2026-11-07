# Standalone build for the trapkit engine module.
#
#   make            # build/kmod/trapkit.ko
#   make load       # insmod (no device; the engine is inert by itself)
#   make unload     # rmmod trapkit
#   make clean
#
# The engine has no userspace surface: it becomes interesting when an
# application module registers a target on it (build that against
# build/kmod/Module.symvers via KBUILD_EXTRA_SYMBOLS).

KDIR ?= /lib/modules/$(shell uname -r)/build
CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=c11

BUILDDIR := build
TK_SRCDIR := src
TK_HDRS := tk.h tk_internal.h
TK_SRC := tk_main.c tk_target.c tk_bp.c tk_process.c \
          tk_remote.c tk_scan.c tk_x86.c
TK_OBJS := $(TK_SRC:.c=.o)

.PHONY: all module user clean load unload

all: module

module: | $(BUILDDIR)/kmod
	cp -u $(addprefix $(TK_SRCDIR)/,$(TK_HDRS) $(TK_SRC)) $(BUILDDIR)/kmod/
	$(MAKE) -C $(KDIR) M=$(CURDIR)/$(BUILDDIR)/kmod modules

$(BUILDDIR)/kmod:
	mkdir -p $(BUILDDIR)/kmod
	printf 'obj-m += trapkit.o\ntrapkit-objs := $(TK_OBJS)\n' > $(BUILDDIR)/kmod/Makefile

clean:
	rm -rf $(BUILDDIR)

load: module
	sudo insmod $(BUILDDIR)/kmod/trapkit.ko

unload:
	-sudo rmmod trapkit
