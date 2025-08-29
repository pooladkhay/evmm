# Makefile for building and signing a kernel module under Secure Boot

obj-m := evmm.o

KDIR := /lib/modules/$(shell uname -r)/build

PWD := $(shell pwd)

SIGN_KEY ?= $(HOME)/.mok/MOK.priv
SIGN_CERT ?= $(HOME)/.mok/MOK.der

# sign-file script provided by the kernel
SIGN_TOOL := $(KDIR)/scripts/sign-file

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	$(SIGN_TOOL) sha256 $(SIGN_KEY) $(SIGN_CERT) $(PWD)/evmm.ko

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
