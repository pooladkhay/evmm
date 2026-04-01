#include <asm/io.h>
#include <linux/gfp.h>
#include <linux/processor.h>

#include "include/vmx.h"

// TODO: investigate using an array indexed by core id
static DEFINE_PER_CPU(struct evmm_percpu_config, percpu_config) = {
    .orig_cr0 = 0, // core_id-dependent value
    .orig_cr4 = 0, // core_id-dependent value
    .vmxon_region = NULL,
    .vmxon_region_phys = 0,
    .vmxon = false,
    .cr_saved = false,
};

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

void __init evmm_cpu_init(void *info)
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

void evmm_cpu_exit(void *info)
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