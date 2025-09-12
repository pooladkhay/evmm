#define DEBUG
#include <asm/io.h>
#include <asm/msr.h>
#include <asm/paravirt.h>
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

#include "evmm.h"
#include "vmx.h"

static long evmm_ioctl(struct file *filp, unsigned int ioctl,
		       unsigned long arg);

struct evmm_percpu_config {
	unsigned long orig_cr0;
	unsigned long orig_cr4;
	void *vmxon_region;
	void *vmcs_region;
	bool cr_saved;
	bool vmxon;
};
static DEFINE_PER_CPU(struct evmm_percpu_config, evmm_percpu_config) = {
    .orig_cr0 = 0,
    .orig_cr4 = 0,
    .vmxon_region = NULL,
    .vmcs_region = NULL,
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

	ret = rdmsrq_safe(MSR_IA32_FEAT_CTL, &feature_control);
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

static int evmm_cpu_set_cr0_cr4(struct evmm_percpu_config *conf)
{
	int ret = 0;

	conf->orig_cr0 = read_cr0();
	conf->orig_cr4 = __read_cr4();
	conf->cr_saved = true;

	u64 cr0_fixed0, cr0_fixed1, cr4_fixed0, cr4_fixed1;

	ret = rdmsrq_safe(MSR_IA32_VMX_CR0_FIXED0, &cr0_fixed0);
	if (ret) {
		pr_err("evmm: failed to read 'MSR_IA32_VMX_CR0_FIXED0': %d\n",
		       ret);
		return -EIO;
	}

	ret = rdmsrq_safe(MSR_IA32_VMX_CR0_FIXED1, &cr0_fixed1);
	if (ret) {
		pr_err("evmm: failed to read 'MSR_IA32_VMX_CR0_FIXED1': %d\n",
		       ret);
		return -EIO;
	}

	ret = rdmsrq_safe(MSR_IA32_VMX_CR4_FIXED0, &cr4_fixed0);
	if (ret) {
		pr_err("evmm: failed to read 'MSR_IA32_VMX_CR4_FIXED0': %d\n",
		       ret);
		return -EIO;
	}

	ret = rdmsrq_safe(MSR_IA32_VMX_CR4_FIXED1, &cr4_fixed1);
	if (ret) {
		pr_err("evmm: failed to read 'MSR_IA32_VMX_CR4_FIXED1': %d\n",
		       ret);
		return -EIO;
	}

	// fixed MSRs also set 'X86_CR4_VMXE' bit to the correct value
	unsigned long cr0 = (conf->orig_cr0 | cr0_fixed0) & cr0_fixed1;
	unsigned long cr4 = (conf->orig_cr4 | cr4_fixed0) & cr4_fixed1;

	write_cr0(cr0);
	__write_cr4(cr4);

	return ret;
}

static int evmm_cpu_alloc_mem(struct evmm_percpu_config *conf)
{
	int ret = 0;

	void *vmxon_region = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	if (!vmxon_region) {
		pr_err("evmm: failed to allocate vmxon region.\n");
		return -ENOMEM;
	};
	conf->vmxon_region = vmxon_region;

	void *vmcs_region = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	if (!vmcs_region) {
		pr_err("evmm: failed to allocate vmcs region.\n");
		free_page((unsigned long)vmxon_region);
		conf->vmxon_region = NULL;
		return -ENOMEM;
	};
	conf->vmcs_region = vmcs_region;

	u64 basic_msr;
	ret = rdmsrq_safe(MSR_IA32_VMX_BASIC, &basic_msr);
	if (ret) {
		pr_err("evmm: failed to read 'MSR_IA32_VMX_BASIC': %d\n", ret);
		return -EIO;
	}

	u32 revision_id = (u32)(basic_msr & 0x7fffffff);

	*(u32 *)vmxon_region = revision_id;
	*(u32 *)vmcs_region = revision_id;

	return ret;
}

static int evmm_cpu_enter_vmx(struct evmm_percpu_config *conf)
{

	int ret = 0;

	uint8_t asm_err;

	phys_addr_t vmxon_phys_addr = virt_to_phys(conf->vmxon_region);
	if (!IS_ALIGNED((unsigned long)vmxon_phys_addr, 4096)) {
		pr_err("evmm: 'vmxon_phys_addr' is not aligned to 4kb "
		       "boundary.\n");
		return -EINVAL;
	}

	phys_addr_t vmcs_phys_addr = virt_to_phys(conf->vmcs_region);
	if (!IS_ALIGNED((unsigned long)vmcs_phys_addr, 4096)) {
		pr_err("evmm: 'vmcs_phys_addr' is not aligned to 4kb "
		       "boundary.\n");
		return -EINVAL;
	}

	asm_err = vmxon((uint64_t)vmxon_phys_addr);
	if (asm_err) {
		pr_err("evmm: 'vmxon' failed with %d - potential cause: CPU is "
		       "already in vmx-root operation.\n",
		       asm_err);
		return -EIO;
	}
	conf->vmxon = true;

	asm_err = vmclear((uint64_t)vmcs_phys_addr);
	if (asm_err) {
		pr_err("evmm: 'vmclear' failed with %d.\n", asm_err);
		return -EIO;
	}

	asm_err = vmptrld((uint64_t)vmcs_phys_addr);
	if (asm_err) {
		pr_err("evmm: 'vmptrld' failed with %d.\n", asm_err);
		return -EIO;
	}

	return ret;
}

static void __init evmm_per_cpu_init(void *info)
{
	int ret;
	int id = smp_processor_id();
	struct evmm_percpu_config *conf = this_cpu_ptr(&evmm_percpu_config);
	atomic_t *init_cpu_err = (atomic_t *)info;

	/* check if cpu is intel and supports VMX */
	ret = evmm_cpu_check_vmx(id);
	if (ret)
		goto err;

	/* save original then cr0 and cr4 based on fixed0 and fixed1 MSRs */
	ret = evmm_cpu_set_cr0_cr4(conf);
	if (ret)
		goto err;

	/* allocate per-cpu memory regions */
	ret = evmm_cpu_alloc_mem(conf);
	if (ret)
		goto err;

	/* execute VMXON, VMCLEAR and VMPTRLD */
	ret = evmm_cpu_enter_vmx(conf);
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

	struct evmm_percpu_config *cpu_conf;
	cpu_conf = this_cpu_ptr(&evmm_percpu_config);

	if (cpu_conf->vmxon) {
		vmxoff();
		cpu_conf->vmxon = false;
		pr_debug("evmm: CPU #%d: 'vmxoff' executed.\n", cpu_id);
	}

	if (cpu_conf->vmxon_region) {
		free_page((unsigned long)cpu_conf->vmxon_region);
		cpu_conf->vmxon_region = NULL;
		pr_debug("evmm: CPU #%d: 'vmxon_region' freed.\n", cpu_id);
	}

	if (cpu_conf->vmcs_region) {
		free_page((unsigned long)cpu_conf->vmcs_region);
		cpu_conf->vmcs_region = NULL;
		pr_debug("evmm: CPU #%d: 'vmcs_region' freed.\n", cpu_id);
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

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MJ Pooladkhay <mj@pooladkhay.com>");
MODULE_DESCRIPTION("An experimental Virtual Machine Monitor");
