#ifndef _EVMM_ARCH_X86_64_VMX_MSR_H_
#define _EVMM_ARCH_X86_64_VMX_MSR_H_

#include <linux/compiler_attributes.h>
#include <linux/types.h>

// 480H
union ia32_vmx_basic_msr {
	__u64 full;
	struct {
		__u64 vmcs_revision_identifier : 31;
		__u64 always_0 : 1;
		__u64 vmxon_region_size : 13;
		__u64 reserved_1 : 3;
		__u64 vmxon_physical_address_width : 1;
		__u64 dual_monitor_smi : 1;
		__u64 memory_type : 4;
		__u64 io_instruction_reporting : 1;
		__u64 true_controls : 1;
	} bits;
} __packed;

#endif /* _EVMM_ARCH_X86_64_VMX_MSR_H_ */
