MODULE_NAME := evmm
obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-objs := evmm_main.o \
                      arch/x86_64/vmx/msr.o \
                      arch/x86_64/vmx/stub.o

KDIR := /lib/modules/$(shell uname -r)/build

PWD := $(shell pwd)

ccflags-y := -I$(PWD)/arch/x86_64/include

SIGN_KEY ?= $(HOME)/.mok/dev-signing-key.priv
SIGN_CERT ?= $(HOME)/.mok/dev-signing-key.der

# sign-file script provided by the kernel
SIGN_TOOL := $(KDIR)/scripts/sign-file

all: build _auto-install status

sign: build _sign-module

install: _auto-install status

build:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

status:
	@echo "Module status:"
	@if lsmod | grep -q "^$(MODULE_NAME) "; then \
		echo "✓ $(MODULE_NAME) is loaded"; \
		lsmod | grep "^$(MODULE_NAME) "; \
	else \
		echo "✗ $(MODULE_NAME) is not loaded"; \
	fi
	@echo "Device status:"
	@if [ -c /dev/$(MODULE_NAME) ]; then \
		echo "✓ /dev/$(MODULE_NAME) exists"; \
		ls -l /dev/$(MODULE_NAME); \
	else \
		echo "✗ /dev/$(MODULE_NAME) does not exist"; \
	fi

remove:
	sudo rmmod $(MODULE_NAME)

dmesg:
	sudo dmesg -c && clear && sudo dmesg -w

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

lint:
	@echo "Generating compile_commands.json for clangd..."
	$(MAKE) clean
	bear -- $(MAKE) build
	python3 filter_compile_commands.py

_sign-module:
	$(SIGN_TOOL) sha256 $(SIGN_KEY) $(SIGN_CERT) $(PWD)/$(MODULE_NAME).ko

_auto-install:
	@echo "Checking module status..."
	@if lsmod | grep -q "^$(MODULE_NAME) "; then \
		echo "Module $(MODULE_NAME) is loaded, removing..."; \
		sudo rmmod $(MODULE_NAME) || true; \
	fi
	@echo "Installing module $(MODULE_NAME)..."
	sudo insmod $(PWD)/$(MODULE_NAME).ko
	@echo "Module installed successfully!"

.PHONY: all sign install build status remove dmesg clean lint _sign-module _auto-install
