#include <asm/msr.h>
#include <asm/paravirt.h>
#include <linux/atomic.h>
#include <linux/cpufeature.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/processor.h>
#include <linux/smp.h>
#include <linux/uaccess.h>

#include "evmm.h"

static long evmm_ioctl(struct file *filp, unsigned int ioctl,
		       unsigned long arg);

static void __init evmm_init_cpu(void *info);

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
	pr_info("ioctl called.\n");

	void __user *argp = (void __user *)arg;

	switch (ioctl) {
	case EVMM_GET_API_VERSION:
		if (!arg)
			return -EINVAL;

		int api_version = EVMM_API_VERSION;
		if (copy_to_user(argp, &api_version, sizeof(api_version)))
			return -EFAULT;

		return 0;
	default:
		return -ENOTTY;
	}
}

static void __init evmm_init_cpu(void *info)
{
	atomic_t *init_cpu_err = (atomic_t *)info;
	int ret;
	int id = smp_processor_id();
	struct cpuinfo_x86 *cpu = &cpu_data(id);
	u64 feature_control;

	if (cpu->x86_vendor != X86_VENDOR_INTEL) {
		pr_err("evmm: only Intel CPUs are supported.\n");
		ret = -ENODEV;
		goto err;
	}

	if (!cpu_has(cpu, X86_FEATURE_VMX)) {
		pr_err("evmm: Intel VT-x (VMX) is not supported.\n");
		ret = -ENODEV;
		goto err;
	}

	ret = rdmsrq_safe(MSR_IA32_FEAT_CTL, &feature_control);
	if (ret) {
		pr_err("evmm: failed to read Feature Control MSR: %d\n", ret);
		ret = -EIO;
		goto err;
	}

	if (!(feature_control & FEAT_CTL_LOCKED)) {
		pr_err("evmm: Feature Control MSR is not locked.\n");
		ret = -ENODEV;
		goto err;
	}

	if (!(feature_control & FEAT_CTL_VMX_ENABLED_OUTSIDE_SMX)) {
		pr_err("evmm: VMX is disabled in BIOS/UEFI.\n");
		ret = -ENODEV;
		goto err;
	}

	cr4_set_bits(X86_CR4_VMXE);

	unsigned long cr0 = read_cr0();
	unsigned long cr4 = __read_cr4();

	u64 cr0_fixed0, cr0_fixed1, cr4_fixed0, cr4_fixed1;

	rdmsrq_safe(MSR_IA32_VMX_CR0_FIXED0, &cr0_fixed0);
	rdmsrq_safe(MSR_IA32_VMX_CR0_FIXED1, &cr0_fixed1);
	rdmsrq_safe(MSR_IA32_VMX_CR4_FIXED0, &cr4_fixed0);
	rdmsrq_safe(MSR_IA32_VMX_CR4_FIXED1, &cr4_fixed1);

	cr0 = (cr0 | cr0_fixed0) & cr0_fixed1;
	cr4 = (cr4 | cr4_fixed0) & cr4_fixed1;

	write_cr0(cr0);
	__write_cr4(cr4);

	pr_info("evmm: cpu #%d init done.\n", id);
	return;

err:
	atomic_set(init_cpu_err, ret);
}

static int __init evmm_init(void)
{
	pr_info("evmm: module init.\n");

#ifndef CONFIG_X86_64
	pr_warn("evmm: only supports Intel x86_64 CPUs.");
	return -ENODEV;
#else
	int ret;
	atomic_t init_cpu_err;

	atomic_set(&init_cpu_err, 0);

	on_each_cpu(evmm_init_cpu, &init_cpu_err, 1);

	int cpu_init_err = atomic_read(&init_cpu_err);
	if (cpu_init_err)
		return cpu_init_err;

	ret = misc_register(&evmm_dev);
	if (ret) {
		pr_err("evmm: failed to register misc device: %d\n", ret);
		return ret;
	}

	pr_info("evmm: successfully initialized.\n");
	return 0;
#endif
}

static void __exit evmm_exit(void)
{
	pr_info("evmm: module exit.\n");

	misc_deregister(&evmm_dev);
}

module_init(evmm_init);
module_exit(evmm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MJ Pooladkhay <mj@pooladkhay.com>");
MODULE_DESCRIPTION("An experimental Virtual Machine Monitor");
