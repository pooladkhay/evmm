#include "./include/msr.h"
#include <linux/types.h>

__u64 evmm_rdmsr_unsafe(__u32 msr)
{
	__u64 val = 0;
	int err;

	err = evmm_rdmsr(msr, &val);
	if (err) {
		pr_err("evmm: failed to read MSR 0x%x: %d\n", msr, err);
	}
	return val;
}
