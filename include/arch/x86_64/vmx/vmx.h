
#ifndef _EVMM_ARCH_X86_64_VMX_H_
#define _EVMM_ARCH_X86_64_VMX_H_

#include <linux/compiler_attributes.h>
#include <linux/preempt.h>
#include <linux/types.h>

struct evmm_vmxon_region {
	union {
		__u32 full;
		struct {
			__u32 revision_identifier : 31;
			__u32 must_be_zeroed : 1;
		} bits;
	} header;
} __packed;

struct evmm_percpu_config {
	unsigned long orig_cr0;
	unsigned long orig_cr4;
	struct evmm_vmxon_region *vmxon_region;
	phys_addr_t vmxon_region_phys;
	bool cr_saved;
	bool vmxon;
};

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

static inline unsigned long read_dr_safe(unsigned int n)
{
	unsigned long val;

	preempt_disable(); /* stay on same CPU */
	switch (n) {
	case 0:
		asm volatile("mov %%dr0, %0" : "=r"(val));
		break;
	case 1:
		asm volatile("mov %%dr1, %0" : "=r"(val));
		break;
	case 2:
		asm volatile("mov %%dr2, %0" : "=r"(val));
		break;
	case 3:
		asm volatile("mov %%dr3, %0" : "=r"(val));
		break;
	case 6:
		asm volatile("mov %%dr6, %0" : "=r"(val));
		break;
	case 7:
		asm volatile("mov %%dr7, %0" : "=r"(val));
		break;
	default:
		val = 0; /* invalid register */
	}
	preempt_enable();
	return val;
}

static inline unsigned long read_rflags_safe(void)
{
	unsigned long flags;

	preempt_disable(); /* stay on same CPU */
	asm volatile("pushfq; popq %0" : "=r"(flags));
	preempt_enable();

	return flags;
}

#endif /* _EVMM_ARCH_X86_64_VMX_H_ */
