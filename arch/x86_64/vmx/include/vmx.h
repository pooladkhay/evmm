#ifndef EVMM_ARCH_X86_64_VMX_H
#define EVMM_ARCH_X86_64_VMX_H

#include <asm/desc_defs.h>
#include <asm/segment.h>
#include <linux/compiler_attributes.h>
#include <linux/preempt.h>
#include <linux/types.h>

#include "msr.h"
#include "vmcs.h"

#define EVMM_EXIT_REASON_EXCEPTION_OR_NMI 0
#define EVMM_EXIT_REASON_EXT_INTR 1
#define EVMM_EXIT_REASON_HLT 12

struct evmm_vmxon_region {
	union {
		__u32 full;
		struct {
			__u32 revision_identifier : 31;
			__u32 must_be_zeroed : 1;
		} bits;
	} header;
} __packed;

// per vcpu config
struct evmm_vcpu {
	void *guest_stack;
	struct evmm_vmcs *vmcs_region;
	phys_addr_t vmcs_region_phys;
	void *msr_bitmap;
	phys_addr_t msr_bitmap_phys;
	void *orig_host_rsp; // the kernel stack that has initiated a vm run
	void *host_stack;    // base address of stack
	void *host_rsp;	     // rsp to be used for passing vcpu*
	u64 launched;
	struct {
		__u64 rax, rcx, rdx, rbx;
		__u64 rsp, rbp, rsi, rdi;
		__u64 r8, r9, r10, r11;
		__u64 r12, r13, r14, r15;
	} gprs;
};

// per physical/logical cpu config
struct evmm_percpu_config {
	unsigned long orig_cr0;
	unsigned long orig_cr4;
	struct evmm_vmxon_region *vmxon_region;
	phys_addr_t vmxon_region_phys;
	bool cr_saved;
	bool vmxon;
};

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

struct desc64 {
	uint16_t limit0;
	uint16_t base0;
	unsigned base1 : 8, type : 4, s : 1, dpl : 2, p : 1;
	unsigned limit1 : 4, avl : 1, l : 1, db : 1, g : 1, base2 : 8;
	uint32_t base3;
	uint32_t zero1;
} __attribute__((packed));

static inline uint64_t get_desc64_base(const struct desc64 *desc)
{
	return ((uint64_t)desc->base3 << 32) |
	       (desc->base0 | ((desc->base1) << 16) | ((desc->base2) << 24));
}

/* VMX Instructions */

static inline int vmxon(__u64 phys)
{
	__u8 ret;

	__asm__ __volatile__("vmxon %[pa]; setna %[ret]"
			     : [ret] "=rm"(ret)
			     : [pa] "m"(phys)
			     : "cc", "memory");

	return ret;
}

static inline void vmxoff(void)
{
	__asm__ __volatile__("vmxoff");
}

static inline int vmclear(__u64 vmcs_pa)
{
	__u8 ret;

	__asm__ __volatile__("vmclear %[pa]; setna %[ret]"
			     : [ret] "=rm"(ret)
			     : [pa] "m"(vmcs_pa)
			     : "cc", "memory");

	return ret;
}

static inline int vmptrld(__u64 vmcs_pa)
{
	__u8 ret;

	__asm__ __volatile__("vmptrld %[pa]; setna %[ret]"
			     : [ret] "=rm"(ret)
			     : [pa] "m"(vmcs_pa)
			     : "cc", "memory");

	return ret;
}

static inline int vmread(__u64 encoding, __u64 *value)
{
	__u64 tmp;
	__u8 ret;

	__asm__ __volatile__("vmread %[encoding], %[value]; setna %[ret]"
			     : [value] "=rm"(tmp), [ret] "=rm"(ret)
			     : [encoding] "r"(encoding)
			     : "cc", "memory");

	*value = tmp;
	return ret;
}

/*
 * A wrapper around vmread that ignores errors and returns zero if the
 * vmread instruction fails.
 */
static inline __u64 vmreadz(__u64 encoding)
{
	__u64 value = 0;
	vmread(encoding, &value);
	return value;
}

static inline int vmwrite(__u64 encoding, __u64 value)
{
	__u8 ret;

	__asm__ __volatile__("vmwrite %[value], %[encoding]; setna %[ret]"
			     : [ret] "=rm"(ret)
			     : [value] "rm"(value), [encoding] "r"(encoding)
			     : "cc", "memory");

	return ret;
}

static inline uint16_t get_es(void)
{
	uint16_t es;

	__asm__ __volatile__("mov %%es, %[es]" : [es] "=rm"(es));
	return es;
}

static inline uint16_t get_cs(void)
{
	uint16_t cs;

	__asm__ __volatile__("mov %%cs, %[cs]" : [cs] "=rm"(cs));
	return cs;
}

static inline uint16_t get_ss(void)
{
	uint16_t ss;

	__asm__ __volatile__("mov %%ss, %[ss]" : [ss] "=rm"(ss));
	return ss;
}

static inline uint16_t get_ds(void)
{
	uint16_t ds;

	__asm__ __volatile__("mov %%ds, %[ds]" : [ds] "=rm"(ds));
	return ds;
}

static inline uint16_t get_fs(void)
{
	uint16_t fs;

	__asm__ __volatile__("mov %%fs, %[fs]" : [fs] "=rm"(fs));
	return fs;
}

static inline uint16_t get_gs(void)
{
	uint16_t gs;

	__asm__ __volatile__("mov %%gs, %[gs]" : [gs] "=rm"(gs));
	return gs;
}

static inline uint16_t get_tr(void)
{
	uint16_t tr;

	__asm__ __volatile__("str %[tr]" : [tr] "=rm"(tr));
	return tr;
}

static inline struct desc_ptr get_gdt(void)
{
	struct desc_ptr gdt;
	__asm__ __volatile__("sgdt %[gdt]" : [gdt] "=m"(gdt));
	return gdt;
}

static inline struct desc_ptr get_idt(void)
{
	struct desc_ptr idt;
	__asm__ __volatile__("sidt %[idt]" : [idt] "=m"(idt));
	return idt;
}

static inline __u32 evmm_adjust_control_field(unsigned int msr, __u64 value)
{
	__u64 msr_value = evmm_rdmsr_unsafe(msr);
	// if a bit is 1, then it must be 1 in the control field
	__u32 allowed_0 = (__u32)msr_value;
	// if a bit is 0, the it must be 0 in the control field
	__u32 allowed_1 = (__u32)(msr_value >> 32);

	return (((__u32)value | allowed_0) & allowed_1);
}

// static inline unsigned long read_dr_safe(unsigned int n)
// {
// 	unsigned long val;

// 	preempt_disable(); /* stay on same CPU */
// 	switch (n) {
// 	case 0:
// 		asm volatile("mov %%dr0, %0" : "=r"(val));
// 		break;
// 	case 1:
// 		asm volatile("mov %%dr1, %0" : "=r"(val));
// 		break;
// 	case 2:
// 		asm volatile("mov %%dr2, %0" : "=r"(val));
// 		break;
// 	case 3:
// 		asm volatile("mov %%dr3, %0" : "=r"(val));
// 		break;
// 	case 6:
// 		asm volatile("mov %%dr6, %0" : "=r"(val));
// 		break;
// 	case 7:
// 		asm volatile("mov %%dr7, %0" : "=r"(val));
// 		break;
// 	default:
// 		val = 0; /* invalid register */
// 	}
// 	preempt_enable();
// 	return val;
// }

// static inline unsigned long read_rflags_safe(void)
// {
// 	unsigned long flags;

// 	preempt_disable(); /* stay on same CPU */
// 	asm volatile("pushfq; popq %0" : "=r"(flags));
// 	preempt_enable();

// 	return flags;
// }

#endif /* EVMM_ARCH_X86_64_VMX_H */
