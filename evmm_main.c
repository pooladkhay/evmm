// #define DEBUG
#include <asm/io.h>
#include <asm/mmu_context.h>
#include <linux/atomic.h>
#include <linux/cpufeature.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/limits.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/percpu-defs.h>
#include <linux/preempt.h>
#include <linux/printk.h>
#include <linux/processor.h>
#include <linux/smp.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include "arch/x86_64/vmx/include/vmcs.h"
#include "arch/x86_64/vmx/include/vmx.h"
#include "include/uapi/evmm.h"

/*
 * IMPORTANT:
 *
 * Although this is 'evmm_main.c', and outside of arch directory but it
 * still contains architecture specific code hence refactor is required.
 * (TODO)
 */

MODULE_AUTHOR("MJ Pooladkhay <mj@pooladkhay.com>");
MODULE_DESCRIPTION("An experimental Virtual Machine Monitor");
MODULE_LICENSE("GPL");

#define EVMM_API_VERSION 1

#define GUEST_STACK_SIZE PAGE_SIZE

// TODO: investigate using an array indexed by core id
static DEFINE_PER_CPU(struct evmm_percpu_config, percpu_config) = {
    .orig_cr0 = 0, // core_id-dependent value
    .orig_cr4 = 0, // core_id-dependent value
    .vmxon_region = NULL,
    .vmxon_region_phys = 0,
    .vmxon = false,
    .cr_saved = false,
};

static __read_mostly struct preempt_ops evmm_preempt_ops;

static void guest_print(unsigned long value)
{
	/* * VMCALL instruction.
	 * We pass a "Hypercall ID" in RAX (e.g., 0x1)
	 * and the value to print in RBX.
	 */
	asm volatile("mov $1, %%rax \n\t"
		     "mov %0, %%rbx \n\t"
		     "vmcall"
		     :
		     : "r"(value)
		     : "rax", "rbx", "memory");
}

static void temp_guest_entrypoint(void)
{
	for (unsigned long i = 0; i <= 100000000000; i++) {
		if (i % 100000000 == 0) {
			guest_print(i / 100000000);
			asm volatile("pause");
		}
	}
	asm volatile("hlt");
}

static int evmm_exit_handler(struct evmm_vcpu *vcpu)
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

static void evmm_save_exit_info(struct evmm_vcpu *vcpu)
{
	vcpu->exit_info.exit_reason.full =
	    (u32)vmreadz(VMEXIT_INFO_EXIT_REASON);
	vcpu->exit_info.instruction_length =
	    (u32)vmreadz(VMEXIT_INFO_VM_EXIT_INSTRUCTION_LENGTH);
	vcpu->exit_info.intr_info.full =
	    (u32)vmreadz(VMEXIT_INFO_VM_EXIT_INTERRUPTION_INFORMATION);
	vcpu->guest_rip = vmreadz(GUEST_RIP);
}

static void evmm_init_guest_state(void *guest_rip, void *guest_rsp)
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

static void evmm_init_host_state(void *host_rip, void *host_rsp)
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

static void evmm_init_control_state(phys_addr_t msr_bitmap_phys_addr,
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

static void evmm_init_vmcs(phys_addr_t msr_bitmap_phys_addr,
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
static int evmm_vcpu_init(struct evmm_vcpu *vcpu, void *host_entrypoint,
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

static struct evmm_vcpu *evmm_vcpu_create(void)
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

static void evmm_vcpu_destroy(struct evmm_vcpu *vcpu)
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

/* Section: Initialize logical CPU(s) and run VMXON */

static int evmm_cpu_check_vmx(int cpu_id)
{
	int ret = 0;
	struct cpuinfo_x86 *cpu = &cpu_data(cpu_id);
	u64 feature_control;

	if (cpu->x86_vendor != X86_VENDOR_INTEL) {
		pr_err("evmm: only Intel CPUs are supported.\n");
		return -ENODEV;
	}

	if (!cpu_has(cpu, X86_FEATURE_VMX)) {
		pr_err("evmm: Intel VT-x (VMX) is not supported.\n");
		return -ENODEV;
	}

	ret = evmm_rdmsr(MSR_IA32_FEAT_CTL, &feature_control);
	if (ret) {
		pr_err("evmm: failed to read Feature Control MSR: %d\n", ret);
		return -EIO;
	}

	if (!(feature_control & FEAT_CTL_LOCKED)) {
		pr_err("evmm: Feature Control MSR is not locked.\n");
		return -ENODEV;
	}

	if (!(feature_control & FEAT_CTL_VMX_ENABLED_OUTSIDE_SMX)) {
		pr_err("evmm: VMX is disabled in BIOS/UEFI.\n");
		return -ENODEV;
	}

	return ret;
}

static int evmm_cpu_set_cr0_cr4(struct evmm_percpu_config *cpu_conf)
{
	int ret = 0;

	u64 cr0_fixed0, cr0_fixed1, cr4_fixed0, cr4_fixed1;

	ret = evmm_rdmsr(MSR_IA32_VMX_CR0_FIXED0, &cr0_fixed0);
	if (ret) {
		pr_err("evmm: failed to read 'MSR_IA32_VMX_CR0_FIXED0': %d\n",
		       ret);
		return -EIO;
	}

	ret = evmm_rdmsr(MSR_IA32_VMX_CR0_FIXED1, &cr0_fixed1);
	if (ret) {
		pr_err("evmm: failed to read 'MSR_IA32_VMX_CR0_FIXED1': %d\n",
		       ret);
		return -EIO;
	}

	ret = evmm_rdmsr(MSR_IA32_VMX_CR4_FIXED0, &cr4_fixed0);
	if (ret) {
		pr_err("evmm: failed to read 'MSR_IA32_VMX_CR4_FIXED0': %d\n",
		       ret);
		return -EIO;
	}

	ret = evmm_rdmsr(MSR_IA32_VMX_CR4_FIXED1, &cr4_fixed1);
	if (ret) {
		pr_err("evmm: failed to read 'MSR_IA32_VMX_CR4_FIXED1': %d\n",
		       ret);
		return -EIO;
	}

	cpu_conf->orig_cr0 = read_cr0();
	cpu_conf->orig_cr4 = __read_cr4();
	cpu_conf->cr_saved = true;

	// fixed MSRs also set 'X86_CR4_VMXE' bit to the correct value (1)
	unsigned long cr0 = (cpu_conf->orig_cr0 | cr0_fixed0) & cr0_fixed1;
	unsigned long cr4 = (cpu_conf->orig_cr4 | cr4_fixed0) & cr4_fixed1;

	write_cr0(cr0);
	__write_cr4(cr4);

	return ret;
}

static int evmm_cpu_vmxon(struct evmm_percpu_config *cpu_conf)
{
	int ret = 0;
	int asm_err;

	cpu_conf->vmxon_region = (struct evmm_vmxon_region *)__get_free_page(
	    GFP_KERNEL | __GFP_ZERO);
	if (!cpu_conf->vmxon_region) {
		pr_err("evmm: failed to allocate vmxon region.\n");
		ret = -ENOMEM;
		goto err_ret;
	};

	union ia32_vmx_basic_msr basic_msr;
	ret = evmm_rdmsr(MSR_IA32_VMX_BASIC, &basic_msr.full);
	if (ret) {
		pr_err("evmm: failed to read 'MSR_IA32_VMX_BASIC': %d\n", ret);
		ret = -EIO;
		goto err_free_vmxon;
	}

	cpu_conf->vmxon_region->header.bits.revision_identifier =
	    basic_msr.bits.vmcs_revision_identifier;
	cpu_conf->vmxon_region->header.bits.must_be_zeroed = 0;

	cpu_conf->vmxon_region_phys = virt_to_phys(cpu_conf->vmxon_region);
	if (!IS_ALIGNED((unsigned long)cpu_conf->vmxon_region_phys,
			PAGE_SIZE)) {
		pr_err("evmm: 'vmxon_phys_addr' is not aligned to 4kb "
		       "boundary.\n");
		ret = -EINVAL;
		goto err_free_vmxon;
	}

	asm_err = vmxon(cpu_conf->vmxon_region_phys);
	if (asm_err) {
		pr_err("evmm: 'vmxon' failed with %d - potential cause: CPU is "
		       "already in vmx-root operation.\n",
		       asm_err);
		ret = -EIO;
		goto err_free_vmxon;
	}
	cpu_conf->vmxon = true;

	return 0;

err_free_vmxon:
	free_page((unsigned long)cpu_conf->vmxon_region);
	cpu_conf->vmxon_region = NULL;
	cpu_conf->vmxon_region_phys = 0;
err_ret:
	return ret;
}

static void __init evmm_cpu_init(void *info)
{
	int ret;

	int id = get_cpu();
	struct evmm_percpu_config *cpu_conf = this_cpu_ptr(&percpu_config);
	atomic_t *init_cpu_err = (atomic_t *)info;

	/* check if cpu is intel and supports VMX */
	ret = evmm_cpu_check_vmx(id);
	if (ret)
		goto err;

	/* save original then cr0 and cr4 based on fixed0 and fixed1 MSRs */
	ret = evmm_cpu_set_cr0_cr4(cpu_conf);
	if (ret)
		goto err;

	/* allocate per-cpu memory region for vmxon and enter vmx */
	ret = evmm_cpu_vmxon(cpu_conf);
	if (ret)
		goto err;

	pr_debug("evmm: CPU #%d: init done.\n", id);
	put_cpu();

	return;

err:
	atomic_set(init_cpu_err, ret);
	put_cpu();
}

/* Section: Deinitialize logical CPU(s) and run VMXOFF */

static void evmm_cpu_exit(void *info)
{
	int cpu_id = get_cpu();

	struct evmm_percpu_config *cpu_conf = this_cpu_ptr(&percpu_config);

	if (cpu_conf->vmxon) {
		vmxoff();
		cpu_conf->vmxon = false;
		pr_debug("evmm: CPU #%d: 'vmxoff' executed.\n", cpu_id);
	}

	if (cpu_conf->vmxon_region) {
		free_page((unsigned long)cpu_conf->vmxon_region);
		cpu_conf->vmxon_region = NULL;
		cpu_conf->vmxon_region_phys = 0;
		pr_debug("evmm: CPU #%d: 'vmxon_region' freed.\n", cpu_id);
	}

	if (cpu_conf->cr_saved) {
		write_cr0(cpu_conf->orig_cr0);
		__write_cr4(cpu_conf->orig_cr4);
		cpu_conf->orig_cr0 = 0;
		cpu_conf->orig_cr4 = 0;
		cpu_conf->cr_saved = false;
		pr_debug("evmm: CPU #%d: CR0 and CR4 reverted back to original "
			 "values.\n",
			 cpu_id);
	}

	// TODO: cleanup all allocated vcpu structures

	pr_debug("evmm: CPU #%d: cleanup done.\n", cpu_id);

	put_cpu();
}

/* Section: ioctl */

// static long evmm_vcpu_ioctl(struct file *filep, unsigned int ioctl,
// 			    unsigned long arg)
// {
// 	pr_debug("evmm: vcpu ioctl called.\n");

// 	void __user *argp = (void __user *)arg;

// 	switch (ioctl) {
// 	case EVMM_VCPU_RUN: {
// 	}
// 	default:
// 		return -ENOTTY;
// 	}
// }

// static long evmm_vm_ioctl(struct file *filep, unsigned int ioctl,
// 			  unsigned long arg)
// {
// 	pr_debug("evmm: vm ioctl called.\n");

// 	void __user *argp = (void __user *)arg;

// 	switch (ioctl) {
// 	case EVMM_VCPU_CREATE: {
// 	}
// 	default:
// 		return -ENOTTY;
// 	}
// }

static long evmm_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg)
{
	pr_debug("evmm: ioctl called.\n");

	void __user *argp = (void __user *)arg;

	switch (ioctl) {
	case EVMM_GET_API_VERSION: {

		int api_version = EVMM_API_VERSION;
		if (!arg)
			return -EINVAL;

		if (copy_to_user(argp, &api_version, sizeof(api_version)))
			return -EFAULT;

		return 0;
	}
	case EVMM_VM_CREATE: {
		pr_warn("evmm: 'EVMM_VM_CREATE' is not implemented yet.\n");

		return -ENOTTY;
	}
	// TODO: move to vm_fd ioctl above
	case EVMM_VCPU_CREATE: {
		pr_debug("evmm: 'EVMM_VCPU_CREATE' was called.\n");

		struct evmm_vcpu *vcpu = evmm_vcpu_create();
		if (!vcpu) {
			pr_err("evmm: failed to create vcpu.\n");
			return -ENOMEM;
		}

		// TODO: this MVP instantly runs the created vcpu which is not
		// desirable.

		preempt_disable();
		evmm_vcpu_init(vcpu, __vmx_host_entrypoint,
			       temp_guest_entrypoint);
		vcpu->last_core_id = smp_processor_id();
		preempt_notifier_init(&vcpu->pn, &evmm_preempt_ops);
		preempt_notifier_register(&vcpu->pn);
		preempt_enable();

		int ret;

		while (1) {

			if (signal_pending(current)) {
				pr_info(
				    "evmm: signal pending, exiting VMM loop\n");
				goto out;
			}

			preempt_disable();
			local_irq_disable();

			evmm_init_host_state(NULL, NULL);

			vmwrite(GUEST_RIP, (u64)vcpu->guest_rip);

			volatile unsigned long dd = 0xDEADBEEFCAFE;

			ret = __vmx_vcpu_run(vcpu);

			evmm_save_exit_info(vcpu);

			if (dd != 0xDEADBEEFCAFE) {
				local_irq_enable();
				preempt_enable();
				panic("EVMM: Stack corruption detected! "
				      "Variable dd overwritten.");
			}

			local_irq_enable();
			preempt_enable();

			if (unlikely(ret)) {
				// TODO: refactor and move to exit handler
				unsigned long error =
				    vmreadz(VMEXIT_INFO_VM_INSTRUCTION_ERROR);
				pr_err("evmm: VMLAUNCH failed! Error code: %d. "
				       "Instruction "
				       "Error: %lu\n",
				       ret, error);
				goto out;
			}

			ret = evmm_exit_handler(vcpu);
			if (unlikely(ret)) {
				pr_warn("evmm: exit handler returned: %d - "
					"aborting...\n",
					ret);
				goto out;
			}

			if (need_resched()) {
				pr_info("evmm: need resched\n");
				cond_resched();
			}
		}

	out:
		preempt_notifier_unregister(&vcpu->pn);
		evmm_vcpu_destroy(vcpu);

		int t = 69;
		if (copy_to_user(argp, &t, sizeof(t)))
			return -EFAULT;

		// TODO: return vcpu fd and store vcpu somewhere (?)
		pr_info("ioctl returned.\n");
		return 0;
	}
	default:
		return -ENOTTY;
	}
}

static void sched_in(struct preempt_notifier *notifier, int cpu)
{

	int pc = preempt_count();
	if (pc == 0) {
		pr_err("evmm: BUG! sched_in called with preemption enabled!\n");
	}

	struct evmm_vcpu *vcpu = container_of(notifier, struct evmm_vcpu, pn);

	__u32 abort_ind = vcpu->vmcs_region->abort_indicator;
	if (abort_ind)
		pr_alert("evmm: sched_in: abort_indicator: %d - core: #%d",
			 abort_ind, smp_processor_id());

	if (cpu != vcpu->last_core_id)
		pr_info("evmm: sched_in: moving vmcs %d --> %d\n",
			vcpu->last_core_id, cpu);

	int err = vmptrld((__u64)vcpu->vmcs_region_phys);
	if (err) {
		pr_err("evmm: 'vmptrld' failed with %d.\n", err);
	}

	evmm_init_host_state(NULL, NULL);

	vmwrite(GUEST_RIP, (u64)vcpu->guest_rip);

	vcpu->last_core_id = cpu;
}

static void sched_out(struct preempt_notifier *notifier,
		      struct task_struct *next)
{
	struct evmm_vcpu *vcpu = container_of(notifier, struct evmm_vcpu, pn);

	__u32 abort_ind = vcpu->vmcs_region->abort_indicator;
	if (abort_ind)
		pr_alert("evmm: sched_out: abort_indicator: %d - core: #%d",
			 abort_ind, smp_processor_id());

	int err = vmclear((__u64)vcpu->vmcs_region_phys);
	if (err) {
		pr_err("evmm: 'vmclear' failed with %d.\n", err);
	}

	vcpu->launched = 0;
}

// static struct file_operations evmm_vcpu_ops = {
//     // .release = evmm_vcpu_release,
//     .unlocked_ioctl = evmm_vcpu_ioctl,
//     // .mmap = evmm_vcpu_mmap,
//     .llseek = noop_llseek,
//     .owner = THIS_MODULE,
// };

// static struct file_operations evmm_vm_ops = {
//     // .release = evmm_vm_release,
//     .unlocked_ioctl = evmm_vm_ioctl,
//     .llseek = noop_llseek,
//     .owner = THIS_MODULE,
// };

static struct file_operations evmm_ops = {
    .unlocked_ioctl = evmm_ioctl,
    .llseek = noop_llseek,
    .owner = THIS_MODULE,
};

static struct miscdevice evmm_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "evmm",
    .fops = &evmm_ops,
};

/* Section: Module init */

static int __init evmm_init(void)
{
	pr_debug("evmm: initializing...\n");

#ifndef CONFIG_X86_64
	pr_err("evmm: only supports Intel x86_64 CPUs.\n");
	return -ENODEV;
#else
	int ret;
	atomic_t init_cpu_err;

	atomic_set(&init_cpu_err, 0);

	on_each_cpu(evmm_cpu_init, &init_cpu_err, 1);

	int cpu_init_err = atomic_read(&init_cpu_err);
	if (cpu_init_err) {
		pr_err("evmm: failed to initialize all logical CPUs.\n");
		ret = cpu_init_err;
		goto cpu_cleanup;
	}

	ret = misc_register(&evmm_dev);
	if (ret) {
		pr_err("evmm: failed to register misc device: %d\n", ret);
		goto cpu_cleanup;
	}

	preempt_notifier_inc();
	evmm_preempt_ops.sched_in = sched_in;
	evmm_preempt_ops.sched_out = sched_out;

	pr_info("evmm: successfully initialized.\n");

	return 0;

cpu_cleanup:
	on_each_cpu(evmm_cpu_exit, NULL, 1);
	preempt_notifier_dec();
	return ret;

#endif
}

/* Section: Module exit */

static void __exit evmm_exit(void)
{
	preempt_notifier_dec();
	on_each_cpu(evmm_cpu_exit, NULL, 1);
	misc_deregister(&evmm_dev);
	pr_info("evmm: cleanup successful.\n");
}

module_init(evmm_init);
module_exit(evmm_exit);
