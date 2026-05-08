CC ?= cc

CFLAGS  ?= -O0 -Wall
LDFLAGS ?= -lutil

.PHONY: all musl-shim musl-static

all: exp

exp: exp.c
	$(CC) $(CFLAGS) $(LDFLAGS) -O0 -Wall -o $@ $^
	strip --strip-all $@

ARCH := $(shell uname -m)
MUSL_SHIM_DIR ?= .musl-shim
UAPI_LINUX_DIR ?= /usr/include/linux
UAPI_ASM_GENERIC_DIR ?= /usr/include/asm-generic
UAPI_ASM_DIR ?= /usr/include/$(ARCH)-linux-gnu/asm
musl-shim:
	@test -d "$(UAPI_LINUX_DIR)" || { echo "missing UAPI headers: $(UAPI_LINUX_DIR)" >&2; exit 1; }
	@test -d "$(UAPI_ASM_GENERIC_DIR)" || { echo "missing UAPI headers: $(UAPI_ASM_GENERIC_DIR)" >&2; exit 1; }
	@test -d "$(UAPI_ASM_DIR)" || { echo "missing UAPI headers: $(UAPI_ASM_DIR)" >&2; exit 1; }
	@mkdir -p "$(MUSL_SHIM_DIR)"
	@ln -sfn "$(UAPI_LINUX_DIR)" "$(MUSL_SHIM_DIR)/linux"
	@ln -sfn "$(UAPI_ASM_GENERIC_DIR)" "$(MUSL_SHIM_DIR)/asm-generic"
	@ln -sfn "$(UAPI_ASM_DIR)" "$(MUSL_SHIM_DIR)/asm"

musl-static: musl-shim
	$(MAKE) CC=musl-gcc \
		CFLAGS="$(CFLAGS) -isystem $(CURDIR)/$(MUSL_SHIM_DIR)" LDFLAGS="-static"

clean:
	rm -f exp
