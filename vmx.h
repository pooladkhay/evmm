#include <linux/types.h>

static inline int vmxon(uint64_t phys)
{
	uint8_t ret;

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

static inline int vmclear(uint64_t vmcs_pa)
{
	uint8_t ret;

	__asm__ __volatile__("vmclear %[pa]; setna %[ret]"
			     : [ret] "=rm"(ret)
			     : [pa] "m"(vmcs_pa)
			     : "cc", "memory");

	return ret;
}

static inline int vmptrld(uint64_t vmcs_pa)
{
	uint8_t ret;

	__asm__ __volatile__("vmptrld %[pa]; setna %[ret]"
			     : [ret] "=rm"(ret)
			     : [pa] "m"(vmcs_pa)
			     : "cc", "memory");

	return ret;
}
