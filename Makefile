# Makefile for building and signing a kernel module under Secure Boot

obj-m := evmm.o

KDIR := /lib/modules/$(shell uname -r)/build

PWD := $(shell pwd)

SIGN_KEY ?= $(HOME)/.mok/MOK.priv
SIGN_CERT ?= $(HOME)/.mok/MOK.der

# sign-file script provided by the kernel
SIGN_TOOL := $(KDIR)/scripts/sign-file

MODULE_NAME := evmm

all: build auto-install status

build:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	$(SIGN_TOOL) sha256 $(SIGN_KEY) $(SIGN_CERT) $(PWD)/evmm.ko

auto-install: build
	@echo "Checking module status..."
	@if lsmod | grep -q "^$(MODULE_NAME) "; then \
		echo "Module $(MODULE_NAME) is loaded, removing..."; \
		sudo rmmod $(MODULE_NAME) || true; \
	fi
	@echo "Installing module $(MODULE_NAME)..."
	sudo insmod $(PWD)/evmm.ko
	@echo "Module installed successfully!"

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

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

.PHONY: all build auto-install status remove clean
