
#include <asm/cpu_entry_area.h>
#include <asm/desc.h>
#include <linux/io.h>
#include <linux/percpu-defs.h>
#include <linux/processor.h>
#include <linux/slab.h>
#include <linux/types.h>

#include "include/vcpu.h"
#include "include/vmx.h"

#define GUEST_STACK_SIZE PAGE_SIZE

int evmm_exit_handler(struct evmm_vcpu *vcpu)
{
	pr_debug("evmm: exit handler called\n");

	if (vcpu->exit_info.exit_reason.fields.vm_entry_failure) {
		pr_err("evmm: VM-entry failure detected!\n");
		pr_err("evmm: basic exit reason: %d\n",
		       vcpu->exit_info.exit_reason.fields.basic);
		vcpu->launched = 0;
		return 1;
	}

	switch (vcpu->exit_info.exit_reason.fields.basic) {
	case EVMM_EXIT_REASON_EXCEPTION_OR_NMI:
		if (vcpu->exit_info.intr_info.fields.valid &&
		    vcpu->exit_info.intr_info.fields.type == INTR_TYPE_NMI) {

			pr_info("evmm: hardware NMI on CPU%d\n",
				smp_processor_id());

			pr_info("evmm: NMI exit, re-entering guest\n");

			return 0;
		}
		pr_err("evmm: exit due to non-NMI exception - "
		       "aborting...\n");
		return 1;
	case EVMM_EXIT_REASON_EXT_INTR:
		pr_debug("evmm: exit due to external interrupt\n");

		/*
		 * Only valid if exit_ctls.bits.ack_interrupt_on_exit = 1
		 * This would mean that we don't want linux kernel to handle
		 * interrupts
		 */
		// if (vcpu->exit_info.intr_info.fields.valid) {
		// 	switch (vcpu->exit_info.intr_info.fields.type) {
		// 	case INTR_TYPE_EXTERNAL_INTERRUPT:
		// 		pr_info("evmm: interrupt type: external "
		// 			"interrupt\n");
		// 		break;
		// 	case INTR_TYPE_NMI:
		// 		pr_info("evmm: interrupt type: NMI\n");
		// 		break;
		// 	case INTR_TYPE_HW_EXCEPTION:
		// 		pr_info("evmm: interrupt type: hardware "
		// 			"exception\n");
		// 		break;
		// 	case INTR_TYPE_PRIV_SW_EXCEPTION:
		// 		pr_info("evmm: interrupt type: privileged "
		// 			"software exception\n");
		// 		break;
		// 	case INTR_TYPE_SW_EXCEPTION:
		// 		pr_info("evmm: interrupt type: software "
		// 			"exception\n");
		// 		break;
		// 	default:
		// 		pr_info("evmm: interrupt type: undefined\n");
		// 		break;
		// 	}
		// } else {
		// }
		return 0;
	case EVMM_EXIT_REASON_INIT:
		pr_emerg("evmm: received INIT signal on cpu #%d while guest "
			 "was running.\n",
			 smp_processor_id());

		pr_emerg("evmm: last_core_id: %d\n", vcpu->last_core_id);
		pr_emerg("evmm: GUEST_RIP: 0x%llx\n", vmreadz(GUEST_RIP));
		pr_emerg("evmm: GUEST_RSP: 0x%llx\n", vmreadz(GUEST_RSP));
		pr_emerg("evmm: GUEST_CR3: 0x%llx\n", vmreadz(GUEST_CR3));
		pr_emerg("evmm: guest_rip (saved): 0x%llx\n", vcpu->guest_rip);
		pr_emerg("evmm: guest_stack: %p (phys: 0x%llx)\n",
			 vcpu->guest_stack, virt_to_phys(vcpu->guest_stack));

		// Try to read IDT to see if guest has proper exception handlers
		u64 guest_idtr_base = vmreadz(GUEST_IDTR_BASE);
		u64 guest_idtr_limit = vmreadz(GUEST_IDTR_LIMIT);
		pr_emerg("evmm: GUEST_IDTR: base=0x%llx limit=0x%llx\n",
			 guest_idtr_base, guest_idtr_limit);

		return 1;
	case EVMM_EXIT_REASON_HLT:
		pr_info("evmm: guest executed 'hlt'.\n");
		return 1;
	case EVMM_EXIT_REASON_VMCALL:
		pr_debug("evmm: VMCALL handler\n");
		if (vcpu->gprs.rax == 1) {
			pr_info("%llu\n", vcpu->gprs.rbx);
		}

		vcpu->guest_rip += vcpu->exit_info.instruction_length;

		return 0;
	case EVMM_EXIT_REASON_VMX_PREEMPT_TIMER_EXPIRED:
		pr_debug("evmm: vmx preempt timer expired.\n");
		return 0;
	default:
		pr_err("evmm: unhandled exit reason: %d - aborting...\n",
		       vcpu->exit_info.exit_reason.fields.basic);
		return 1;
	}
}

void evmm_save_exit_info(struct evmm_vcpu *vcpu)
{
	vcpu->exit_info.exit_reason.full =
	    (u32)vmreadz(VMEXIT_INFO_EXIT_REASON);
	vcpu->exit_info.instruction_length =
	    (u32)vmreadz(VMEXIT_INFO_VM_EXIT_INSTRUCTION_LENGTH);
	vcpu->exit_info.intr_info.full =
	    (u32)vmreadz(VMEXIT_INFO_VM_EXIT_INTERRUPTION_INFORMATION);
	vcpu->guest_rip = vmreadz(GUEST_RIP);
}

void evmm_init_guest_state(void *guest_rip, void *guest_rsp)
{
	vmwrite(GUEST_ES_SELECTOR, vmreadz(HOST_ES_SELECTOR));
	vmwrite(GUEST_CS_SELECTOR, vmreadz(HOST_CS_SELECTOR));
	vmwrite(GUEST_SS_SELECTOR, vmreadz(HOST_SS_SELECTOR));
	vmwrite(GUEST_DS_SELECTOR, vmreadz(HOST_DS_SELECTOR));
	vmwrite(GUEST_FS_SELECTOR, vmreadz(HOST_FS_SELECTOR));
	vmwrite(GUEST_GS_SELECTOR, vmreadz(HOST_GS_SELECTOR));
	vmwrite(GUEST_LDTR_SELECTOR, 0);
	vmwrite(GUEST_TR_SELECTOR, vmreadz(HOST_TR_SELECTOR));
	vmwrite(GUEST_INTERRUPT_STATUS_COND, 0);
	vmwrite(GUEST_PML_INDEX_COND, 0);

	vmwrite(GUEST_VMCS_LINK_POINTER, -1ll);
	vmwrite(GUEST_IA32_DEBUGCTL, 0);
	vmwrite(GUEST_IA32_PAT_COND, vmreadz(HOST_IA32_PAT_COND));
	vmwrite(GUEST_IA32_EFER_COND, vmreadz(HOST_IA32_EFER_COND));
	vmwrite(GUEST_IA32_PERF_GLOBAL_CTRL_COND,
		vmreadz(HOST_IA32_PERF_GLOBAL_CTRL_COND));

	vmwrite(GUEST_ES_LIMIT, -1);
	vmwrite(GUEST_CS_LIMIT, -1);
	vmwrite(GUEST_SS_LIMIT, -1);
	vmwrite(GUEST_DS_LIMIT, -1);
	vmwrite(GUEST_FS_LIMIT, -1);
	vmwrite(GUEST_GS_LIMIT, -1);
	vmwrite(GUEST_LDTR_LIMIT, -1);
	vmwrite(GUEST_TR_LIMIT, 0x67);
	vmwrite(GUEST_GDTR_LIMIT, 0xffff);
	vmwrite(GUEST_IDTR_LIMIT, 0xffff);
	vmwrite(GUEST_ES_ACCESS_RIGHTS,
		vmreadz(GUEST_ES_SELECTOR) == 0 ? 0x10000 : 0xc093);
	vmwrite(GUEST_CS_ACCESS_RIGHTS, 0xa09b);
	vmwrite(GUEST_SS_ACCESS_RIGHTS, 0xc093);
	vmwrite(GUEST_DS_ACCESS_RIGHTS,
		vmreadz(GUEST_DS_SELECTOR) == 0 ? 0x10000 : 0xc093);
	vmwrite(GUEST_FS_ACCESS_RIGHTS,
		vmreadz(GUEST_FS_SELECTOR) == 0 ? 0x10000 : 0xc093);
	vmwrite(GUEST_GS_ACCESS_RIGHTS,
		vmreadz(GUEST_GS_SELECTOR) == 0 ? 0x10000 : 0xc093);
	vmwrite(GUEST_LDTR_ACCESS_RIGHTS, 0x10000);
	vmwrite(GUEST_TR_ACCESS_RIGHTS, 0x8b);
	vmwrite(GUEST_INTERRUPTIBILITY_STATE, 0);
	vmwrite(GUEST_ACTIVITY_STATE, 0);
	vmwrite(GUEST_IA32_SYSENTER_CS, vmreadz(HOST_IA32_SYSENTER_CS));
	vmwrite(GUEST_VMX_PREEMPTION_TIMER_VALUE_COND, 0);

	vmwrite(GUEST_CR0, vmreadz(HOST_CR0));
	vmwrite(GUEST_CR3, vmreadz(HOST_CR3));
	vmwrite(GUEST_CR4, vmreadz(HOST_CR4));
	vmwrite(GUEST_ES_BASE, 0);
	vmwrite(GUEST_CS_BASE, 0);
	vmwrite(GUEST_SS_BASE, 0);
	vmwrite(GUEST_DS_BASE, 0);
	vmwrite(GUEST_FS_BASE, vmreadz(HOST_FS_BASE));
	vmwrite(GUEST_GS_BASE, vmreadz(HOST_GS_BASE));
	vmwrite(GUEST_LDTR_BASE, 0);
	vmwrite(GUEST_TR_BASE, vmreadz(HOST_TR_BASE));
	vmwrite(GUEST_GDTR_BASE, vmreadz(HOST_GDTR_BASE));
	vmwrite(GUEST_IDTR_BASE, vmreadz(HOST_IDTR_BASE));
	vmwrite(GUEST_DR7, 0x400);
	if (guest_rsp)
		vmwrite(GUEST_RSP, (u64)guest_rsp);
	if (guest_rip)
		vmwrite(GUEST_RIP, (u64)guest_rip);
	vmwrite(GUEST_RFLAGS, 2);
	vmwrite(GUEST_PENDING_DEBUG_EXCEPTION, 0);
	vmwrite(GUEST_IA32_SYSENTER_ESP, vmreadz(HOST_IA32_SYSENTER_ESP));
	vmwrite(GUEST_IA32_SYSENTER_EIP, vmreadz(HOST_IA32_SYSENTER_EIP));
}

void evmm_init_host_state(void *host_rip, void *host_rsp)
{
	if (host_rip)
		vmwrite(HOST_RIP, (__u64)host_rip);
	if (host_rsp)
		vmwrite(HOST_RSP, (__u64)host_rsp);
	vmwrite(HOST_CR0, read_cr0());
	vmwrite(HOST_CR3, __read_cr3());
	vmwrite(HOST_CR4, __read_cr4());
	vmwrite(HOST_CS_SELECTOR, get_cs() & ~0x7); //__KERNEL_CS?
	vmwrite(HOST_SS_SELECTOR, get_ss() & ~0x7);
	vmwrite(HOST_DS_SELECTOR, get_ds() & ~0x7);
	vmwrite(HOST_ES_SELECTOR, get_es() & ~0x7);
	vmwrite(HOST_FS_SELECTOR, get_fs() & ~0x7);
	vmwrite(HOST_GS_SELECTOR, get_gs() & ~0x7);
	vmwrite(HOST_TR_SELECTOR, get_tr() & ~0x7);
	vmwrite(HOST_GS_BASE, evmm_rdmsr_unsafe(MSR_GS_BASE));
	vmwrite(HOST_FS_BASE, evmm_rdmsr_unsafe(MSR_FS_BASE));
	vmwrite(HOST_GDTR_BASE, get_gdt().address);
	vmwrite(HOST_IDTR_BASE, get_idt().address);
	vmwrite(HOST_IA32_PAT_COND, evmm_rdmsr_unsafe(MSR_IA32_CR_PAT));
	vmwrite(HOST_IA32_EFER_COND, evmm_rdmsr_unsafe(MSR_EFER));

	vmwrite(HOST_TR_BASE,
		(unsigned long)&get_cpu_entry_area(smp_processor_id())
		    ->tss.x86_tss);

	void *gdt = get_current_gdt_ro();
	vmwrite(HOST_GDTR_BASE, (unsigned long)gdt);
}

void evmm_init_control_state(phys_addr_t msr_bitmap_phys_addr,
			     union ia32_vmx_basic_msr basic_msr)
{
	vmwrite(CONTROL_ADDRESS_OF_MSR_BITMAPS_COND, msr_bitmap_phys_addr);
	vmwrite(CONTROL_CR0_GUEST_HOST_MASK, 0);
	vmwrite(CONTROL_CR4_GUEST_HOST_MASK, 0);
	// vmwrite(CONTROL_EXCEPTION_BITMAP,
	// 	0xFFFFFFFF); // does this mean trap on all exceptions?
	vmwrite(CONTROL_EXCEPTION_BITMAP, 0);

	vmwrite(CONTROL_CR0_READ_SHADOW, vmreadz(HOST_CR0));
	vmwrite(CONTROL_CR4_READ_SHADOW, vmreadz(HOST_CR4));

	// TODO: remove after research
	if (!basic_msr.bits.true_controls)
		pr_warn("evmm: basic_msr.bits.true_controls is set to 0\n");

	union ia32_vmx_entry_ctls_msr entry_ctls;
	entry_ctls.full = 0;
	entry_ctls.bits.ia32e_mode_guest = 1;
	entry_ctls.bits.load_ia32_efer = 1;
	entry_ctls.bits.load_ia32_pat = 1;
	__u32 entry_ctls_adjusted = evmm_adjust_control_field(
	    basic_msr.bits.true_controls ? MSR_IA32_VMX_TRUE_ENTRY_CTLS
					 : MSR_IA32_VMX_ENTRY_CTLS,
	    entry_ctls.full);
	vmwrite(CONTROL_VM_ENTRY_CONTROLS, entry_ctls_adjusted);

	union ia32_vmx_exit_ctls_msr exit_ctls;
	exit_ctls.full = 0;
	exit_ctls.bits.host_address_space_size = 1;
	exit_ctls.bits.load_ia32_efer = 1;
	exit_ctls.bits.save_ia32_efer = 1;
	exit_ctls.bits.load_ia32_pat = 1;
	exit_ctls.bits.save_ia32_pat = 1;
	__u32 exit_ctls_adjusted = evmm_adjust_control_field(
	    basic_msr.bits.true_controls ? MSR_IA32_VMX_TRUE_EXIT_CTLS
					 : MSR_IA32_VMX_EXIT_CTLS,
	    exit_ctls.full);
	vmwrite(CONTROL_PRIMARY_VM_EXIT_CONTROLS, exit_ctls_adjusted);

	// TODO: secondary exit check and set is missing

	union ia32_vmx_pinbased_ctls_msr pinbased_ctls;
	pinbased_ctls.full = 0;
	pinbased_ctls.bits.external_interrupt_exiting = 1;
	pinbased_ctls.bits.nmi_exiting = 1;
	__u32 pinbased_ctls_adjusted = evmm_adjust_control_field(
	    basic_msr.bits.true_controls ? MSR_IA32_VMX_TRUE_PINBASED_CTLS
					 : MSR_IA32_VMX_PINBASED_CTLS,
	    pinbased_ctls.full);
	vmwrite(CONTROL_PIN_BASED_VM_EXECUTION_CONTROLS,
		pinbased_ctls_adjusted);

	union ia32_vmx_procbased_ctls_msr procbased_ctls;
	procbased_ctls.full = 0;
	procbased_ctls.bits.hlt_exiting = 1;
	procbased_ctls.bits.use_msr_bitmaps = 1;
	if (evmm_rdmsr_unsafe(MSR_IA32_VMX_PROCBASED_CTLS) & (1ULL << 63))
		procbased_ctls.bits.active_secondary_controls = 1;
	__u32 procbased_ctls_adjusted = evmm_adjust_control_field(
	    basic_msr.bits.true_controls ? MSR_IA32_VMX_TRUE_PROCBASED_CTLS
					 : MSR_IA32_VMX_PROCBASED_CTLS,
	    procbased_ctls.full);
	vmwrite(CONTROL_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
		procbased_ctls_adjusted);

	// The IA32_VMX_PROCBASED_CTLS2 MSR exists only if bit 63 of the
	// IA32_VMX_PROCBASED_CTLS MSR is 1
	if (evmm_rdmsr_unsafe(MSR_IA32_VMX_PROCBASED_CTLS) & (1ULL << 63)) {
		pr_debug("evmm: secondary procbased is supported\n");
		union ia32_vmx_procbased_ctls2_msr secondary_procbased_ctls;
		secondary_procbased_ctls.full = 0;
		secondary_procbased_ctls.bits.enable_rdtscp = 1;
		secondary_procbased_ctls.bits.enable_xsave_xrstor = 1;
		secondary_procbased_ctls.bits.enable_invpcid = 1;
		__u32 secondary_procbased_ctls_adjusted =
		    evmm_adjust_control_field(MSR_IA32_VMX_PROCBASED_CTLS2,
					      secondary_procbased_ctls.full);
		vmwrite(
		    CONTROL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS_COND,
		    secondary_procbased_ctls_adjusted);
	} else {
		pr_debug("evmm: secondary procbased is NOT supported\n");
	}
}

void evmm_init_vmcs(phys_addr_t msr_bitmap_phys_addr,
		    union ia32_vmx_basic_msr basic_msr, void *host_rip,
		    void *host_rsp, void *guest_rip, void *guest_rsp)
{
	evmm_init_host_state(host_rip, host_rsp);
	evmm_init_guest_state(guest_rip, guest_rsp);
	evmm_init_control_state(msr_bitmap_phys_addr, basic_msr);
}

/*
 * When this function returns successfully, vcpu->vmcs is initialized, current
 * and active.
 */
int evmm_vcpu_init(struct evmm_vcpu *vcpu, void *host_entrypoint,
		   void *guest_entrypoint)
{
	int err = 0;

	union ia32_vmx_basic_msr basic_msr;
	err = evmm_rdmsr(MSR_IA32_VMX_BASIC, &basic_msr.full);
	if (err) {
		pr_err("evmm: failed to read 'MSR_IA32_VMX_BASIC': %d\n", err);
		return -EIO;
	}

	vcpu->vmcs_region->header.bits.revision_identifier =
	    basic_msr.bits.vmcs_revision_identifier;
	vcpu->vmcs_region->header.bits.shadow_vmcs_indicator = 0;

	err = vmclear((__u64)vcpu->vmcs_region_phys);
	if (err) {
		pr_err("evmm: 'vmclear' failed with %d.\n", err);
		return -EIO;
	}

	err = vmptrld((__u64)vcpu->vmcs_region_phys);
	if (err) {
		pr_err("evmm: 'vmptrld' failed with %d.\n", err);
		return -EIO;
	}

	/*
	 * '__vmx_vcpu_run' puts vcpu* on top of the host stack to be passed to
	 * '__vmx_host_entrypoint'
	 */

	void *guest_rsp = (void *)((u8 *)vcpu->guest_stack + GUEST_STACK_SIZE);

	evmm_init_vmcs(vcpu->msr_bitmap_phys, basic_msr, host_entrypoint, NULL,
		       guest_entrypoint, guest_rsp);

	vcpu->guest_rip = vmreadz(GUEST_RIP);

	return 0;
}

struct evmm_vcpu *evmm_vcpu_create(void)
{
	struct evmm_vcpu *vcpu =
	    (struct evmm_vcpu *)kzalloc(sizeof(struct evmm_vcpu), GFP_KERNEL);
	if (!vcpu) {
		pr_err("evmm: failed to allocate memory for vcpu.\n");
		return NULL;
	}

	/* Intel SDM, A.1
	 * - Memory pointers must not set bits beyond the processor’s
	 * physical-address width which can determine a processor’s by executing
	 * CPUID with 80000008H in EAX. The physical-address width is returned
	 * in bits 7:0 of EAX.
	 * - If IA32_VMX_BASIC[48] is read as 1, these pointers must not set
	 * any bits in the range 63:32.
	 */
	vcpu->vmcs_region =
	    (struct evmm_vmcs *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	if (!vcpu->vmcs_region) {
		pr_err("evmm: failed to allocate 'vmcs_region'.\n");
		goto err_free_vcpu;
	};

	vcpu->vmcs_region_phys = virt_to_phys(vcpu->vmcs_region);
	if (!IS_ALIGNED((unsigned long)vcpu->vmcs_region_phys, PAGE_SIZE)) {
		pr_err("evmm: 'vmcs_region_phys' is not aligned to 4kb "
		       "boundary.\n");
		goto err_free_vmcs;
	}

	vcpu->msr_bitmap = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	if (!vcpu->msr_bitmap) {
		pr_err("evmm: failed to allocate 'msr_bitmap'.\n");
		goto err_free_vmcs;
	};

	vcpu->msr_bitmap_phys = virt_to_phys(vcpu->msr_bitmap);
	if (!IS_ALIGNED((unsigned long)vcpu->msr_bitmap_phys, PAGE_SIZE)) {
		pr_err("evmm: 'msr_bitmap_phys' is not aligned to 4kb "
		       "boundary.\n");
		goto err_free_msr;
	}

	vcpu->guest_stack = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	if (!vcpu->guest_stack) {
		pr_err("evmm: failed to allocate vcpu guest stack region.\n");
		goto err_free_msr;
	}

	pr_debug("evmm: vcpu created.\n");
	return vcpu;

err_free_msr:
	free_page((unsigned long)vcpu->msr_bitmap);
err_free_vmcs:
	free_page((unsigned long)vcpu->vmcs_region);
err_free_vcpu:
	kfree(vcpu);
	pr_debug("evmm: vcpu creation failed.\n");
	return NULL;
}

void evmm_vcpu_destroy(struct evmm_vcpu *vcpu)
{
	if (!vcpu) {
		pr_err("evmm: vcpu was NULL.\n");
		return;
	}

	preempt_disable();

	int err = vmclear((__u64)vcpu->vmcs_region_phys);
	if (err) {
		pr_err("evmm: 'vmclear' failed with %d.\nreturning early.\n",
		       err);
		return;
	}

	pr_info("evmm: 'vmclear' on core #%d done.\n", smp_processor_id());

	preempt_enable();

	if (vcpu->guest_stack) {
		free_page((unsigned long)vcpu->guest_stack);
		pr_debug("evmm: 'vcpu->guest_stack' freed.\n");
	}
	if (vcpu->msr_bitmap) {
		free_page((unsigned long)vcpu->msr_bitmap);
		pr_debug("evmm: 'vcpu->msr_bitmap' freed.\n");
	}
	if (vcpu->vmcs_region) {
		free_page((unsigned long)vcpu->vmcs_region);
		pr_debug("evmm: 'vcpu->vmcs_region' freed.\n");
	}

	kfree(vcpu);

	pr_info("evmm: vcpu destroyed.\n");
}
