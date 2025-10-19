#define DEBUG
#include <asm/io.h>
#include <asm/msr.h>
#include <asm/processor-flags.h>
#include <linux/atomic.h>
#include <linux/cpufeature.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/percpu-defs.h>
#include <linux/printk.h>
#include <linux/processor.h>
#include <linux/smp.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "include/evmm.h"
#include "include/arch/x86_64/vmx/msr.h"
#include "include/arch/x86_64/vmx/vmx.h"

MODULE_AUTHOR("MJ Pooladkhay <mj@pooladkhay.com>");
MODULE_DESCRIPTION("An experimental Virtual Machine Monitor");
MODULE_LICENSE("GPL");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
#define evmm_rdmsr(rdmsr_args...) rdmsrq_safe(rdmsr_args)
#else
#define evmm_rdmsr(rdmsr_args...) rdmsrl_safe(rdmsr_args)
#endif

static long evmm_ioctl(struct file *filp, unsigned int ioctl,
		       unsigned long arg);

static DEFINE_PER_CPU(struct evmm_percpu_config, percpu_config) = {
    .orig_cr0 = 0,
    .orig_cr4 = 0,
    .vmxon_region = NULL,
    .vmxon_region_phys = 0,
    .vmxon = false,
    .cr_saved = false,
};

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

static long evmm_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg)
{
	pr_debug("ioctl called.\n");

	int api_version = EVMM_API_VERSION;
	void __user *argp = (void __user *)arg;

	switch (ioctl) {
	case EVMM_GET_API_VERSION:
		if (!arg)
			return -EINVAL;

		if (copy_to_user(argp, &api_version, sizeof(api_version)))
			return -EFAULT;

		return 0;
	default:
		return -ENOTTY;
	}
}

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
		return -ENOMEM;
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
	return ret;
}

static void __init evmm_per_cpu_init(void *info)
{
	int ret;
	int id = smp_processor_id();
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
	return;

err:
	atomic_set(init_cpu_err, ret);
}

static void evmm_per_cpu_exit(void *info)
{
	int cpu_id = smp_processor_id();

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
		pr_debug("evmm: CPU #%d: CR0 and CR4 reverted back to original "
			 "values.\n",
			 cpu_id);
	}

	// TODO: cleanup all allocated vcpu structures

	pr_debug("evmm: CPU #%d: cleanup done.\n", cpu_id);
}

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

	on_each_cpu(evmm_per_cpu_init, &init_cpu_err, 1);

	int cpu_init_err = atomic_read(&init_cpu_err);
	if (cpu_init_err) {
		pr_err("failed to initialise all logical CPUs.\n");
		ret = cpu_init_err;
		goto cpu_cleanup;
	}

	ret = misc_register(&evmm_dev);
	if (ret) {
		pr_err("evmm: failed to register misc device: %d\n", ret);
		goto cpu_cleanup;
	}

	pr_info("evmm: successfully initialized.\n");
	return 0;

cpu_cleanup:
	on_each_cpu(evmm_per_cpu_exit, NULL, 1);
	return ret;

#endif
}

static void __exit evmm_exit(void)
{
	on_each_cpu(evmm_per_cpu_exit, NULL, 1);
	misc_deregister(&evmm_dev);
	pr_info("evmm: cleanup successful.\n");
}

module_init(evmm_init);
module_exit(evmm_exit);
