#ifndef EVMM_ARCH_X86_64_VMX_MSR_H
#define EVMM_ARCH_X86_64_VMX_MSR_H

#include <asm/msr.h>
#include <linux/compiler_attributes.h>
#include <linux/types.h>
#include <linux/version.h>

/* Unsafe MSR reading compatibility */
__u64 evmm_rdmsr_unsafe(__u32 msr);

/* Safe MSR reading compatibility */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
#define evmm_rdmsr(rdmsr_args...) rdmsrq_safe(rdmsr_args)
#else
#define evmm_rdmsr(rdmsr_args...) rdmsrl_safe(rdmsr_args)
#endif

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
		__u64 deliver_hw_exception : 1;
		// 63:57 are reserved
	} bits;
} __packed;

/* VM-Entry Controls - SDM A.5 */

// 484H
union ia32_vmx_entry_ctls_msr {
	__u64 full;
	struct {
		__u64 reserved_0 : 2;
		__u64 load_dbg_controls : 1;
		__u64 reserved_1 : 6;
		__u64 ia32e_mode_guest : 1;
		__u64 entry_to_smm : 1;
		__u64 deactivate_dual_monitor_treament : 1;
		__u64 reserved_3 : 1;
		__u64 load_ia32_perf_global_control : 1;
		__u64 load_ia32_pat : 1;
		__u64 load_ia32_efer : 1;
		__u64 load_ia32_bndcfgs : 1;
		__u64 conceal_vmx_from_pt : 1;
	} bits;
} __packed;

/* VM-Exit Controls - SDM A.4 */

// 483H
union ia32_vmx_exit_ctls_msr {
	__u64 full;
	struct {
		__u64 reserved_0 : 2;
		__u64 save_dbg_controls : 1;
		__u64 reserved_1 : 6;
		__u64 host_address_space_size : 1;
		__u64 reserved_2 : 2;
		__u64 load_ia32_perf_global_control : 1;
		__u64 reserved_3 : 2;
		__u64 ack_interrupt_on_exit : 1;
		__u64 reserved_4 : 2;
		__u64 save_ia32_pat : 1;
		__u64 load_ia32_pat : 1;
		__u64 save_ia32_efer : 1;
		__u64 load_ia32_efer : 1;
		__u64 save_vmx_preemption_timer_value : 1;
		__u64 clear_ia32_bndcfgs : 1;
		__u64 conceal_vmx_from_pt : 1;
	} bits;
} __packed;

/* VM-Execution Controls - SDM A.3 */

// 481H
union ia32_vmx_pinbased_ctls_msr {
	__u64 full;
	struct {
		__u64 external_interrupt_exiting : 1;
		__u64 reserved_0 : 2;
		__u64 nmi_exiting : 1;
		__u64 reserved_1 : 1;
		__u64 virtual_nmis : 1;
		__u64 vmx_preemption_timer : 1;
		__u64 process_posted_interrupts : 1;
	} bits;
} __packed;

// 842H
union ia32_vmx_procbased_ctls_msr {
	__u64 full;
	struct {
		__u64 reserved_0 : 2;
		__u64 interrupt_window_exiting : 1;
		__u64 use_tsc_offsetting : 1;
		__u64 reserved_1 : 3;
		__u64 hlt_exiting : 1;
		__u64 reserved_2 : 1;
		__u64 invldpg_exiting : 1;
		__u64 mwait_exiting : 1;
		__u64 rdpmc_exiting : 1;
		__u64 rdtsc_exiting : 1;
		__u64 reserved_3 : 2;
		__u64 cr3_load_exiting : 1;
		__u64 cr3_store_exiting : 1;
		__u64 reserved_4 : 2;
		__u64 cr8_load_exiting : 1;
		__u64 cr8_store_exiting : 1;
		__u64 use_tpr_shadow : 1;
		__u64 nmi_window_exiting : 1;
		__u64 mov_dr_exiting : 1;
		__u64 unconditional_io_exiting : 1;
		__u64 use_io_bitmaps : 1;
		__u64 reserved_5 : 1;
		__u64 monitor_trap_flag : 1;
		__u64 use_msr_bitmaps : 1;
		__u64 monitor_exiting : 1;
		__u64 pause_exiting : 1;
		__u64 active_secondary_controls : 1;
	} bits;
} __packed;

// 48BH
union ia32_vmx_procbased_ctls2_msr {
	__u64 full;
	struct {
		__u64 virtualize_apic_accesses : 1;
		__u64 enable_ept : 1;
		__u64 descriptor_table_exiting : 1;
		__u64 enable_rdtscp : 1;
		__u64 virtualize_x2apic : 1;
		__u64 enable_vpid : 1;
		__u64 wbinvd_exiting : 1;
		__u64 unrestricted_guest : 1;
		__u64 apic_register_virtualization : 1;
		__u64 virtual_interrupt_delivery : 1;
		__u64 pause_loop_exiting : 1;
		__u64 rdrand_exiting : 1;
		__u64 enable_invpcid : 1;
		__u64 enable_vmfunc : 1;
		__u64 vmcs_shadowing : 1;
		__u64 enable_encls_exiting : 1;
		__u64 rdseed_exiting : 1;
		__u64 enable_pml : 1;
		__u64 use_virtualization_exception : 1;
		__u64 conceal_vmx_from_pt : 1;
		__u64 enable_xsave_xrstor : 1;
		__u64 reserved_0 : 1;
		__u64 mode_based_execute_control_ept : 1;
		__u64 reserved_1 : 2;
		__u64 use_tsc_scaling : 1;
	} bits;
} __packed;

#endif /* EVMM_ARCH_X86_64_VMX_MSR_H */
