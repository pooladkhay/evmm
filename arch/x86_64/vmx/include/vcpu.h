#ifndef EVMM_ARCH_X86_64_VCPU_H
#define EVMM_ARCH_X86_64_VCPU_H

#include <asm/desc_defs.h>
#include <asm/segment.h>
#include <linux/compiler_attributes.h>
#include <linux/preempt.h>
#include <linux/types.h>

#include "msr.h"
#include "vmcs.h"

// per vcpu config
struct evmm_vcpu {
	void *guest_stack;
	struct evmm_vmcs *vmcs_region;
	phys_addr_t vmcs_region_phys;
	void *msr_bitmap;
	phys_addr_t msr_bitmap_phys;
	// the kernel stack that has initiated a vm run
	void *orig_host_rsp;
	// base address of stack - TODO: no longer required. When this field is
	// removed, stub.s must be updated too.
	void *host_stack;
	// rsp to be used for passing vcpu*
	void *host_rsp;
	u32 launched;
	s32 last_core_id;
	struct {
		__u64 rax, rcx, rdx, rbx;
		__u64 rbp, rsi, rdi;
		__u64 r8, r9, r10, r11;
		__u64 r12, r13, r14, r15;
	} gprs;
	u64 guest_rip;
	struct {
		union evmm_vmcs_vmexit_reason exit_reason;
		union evmm_vmcs_vmexit_intr_info intr_info;
		u32 instruction_length;
	} exit_info;
	// TODO: #ifdef CONFIG_PREEMPT_NOTIFIERS
	struct preempt_notifier pn;
	// #endif
};

int evmm_exit_handler(struct evmm_vcpu *vcpu);
void evmm_save_exit_info(struct evmm_vcpu *vcpu);
void evmm_init_guest_state(void *guest_rip, void *guest_rsp);
void evmm_init_host_state(void *host_rip, void *host_rsp);
void evmm_init_control_state(phys_addr_t msr_bitmap_phys_addr,
			     union ia32_vmx_basic_msr basic_msr);
void evmm_init_vmcs(phys_addr_t msr_bitmap_phys_addr,
		    union ia32_vmx_basic_msr basic_msr, void *host_rip,
		    void *host_rsp, void *guest_rip, void *guest_rsp);
int evmm_vcpu_init(struct evmm_vcpu *vcpu, void *host_entrypoint,
		   void *guest_entrypoint);
struct evmm_vcpu *evmm_vcpu_create(void);
void evmm_vcpu_destroy(struct evmm_vcpu *vcpu);
/*
 * returns 1 on VMfailValid or 2 on VMfailInvalid.
 * on success, it will return 0 via a VM exit.
 */
extern int __vmx_vcpu_run(struct evmm_vcpu *vcpu);

/*
 * cpu jumps to this routine on VM exits, stack is restored and '__vmx_vcpu_run'
 * returns with 0.
 */
extern void __vmx_host_entrypoint(void);

#endif