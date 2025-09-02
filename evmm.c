#include <asm/msr.h>
#include <linux/cpufeature.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/processor.h>
#include <linux/uaccess.h>

#include "evmm.h"

static long evmm_ioctl(struct file *filp, unsigned int ioctl,
		       unsigned long arg);

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

static int __init evmm_init(void)
{
	pr_info("evmm: module init.\n");

#ifndef CONFIG_X86_64
	pr_warn("evmm: only supports Intel x86_64 CPUs.");
	return -ENODEV;
#else
	struct cpuinfo_x86 *cpu = &boot_cpu_data;
	u64 feature_control;
	int ret;

	if (cpu->x86_vendor != X86_VENDOR_INTEL) {
		pr_err("evmm: only Intel CPUs are supported.\n");
		return -ENODEV;
	}

	if (!boot_cpu_has(X86_FEATURE_VMX)) {
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

	ret = misc_register(&evmm_dev);
	if (ret) {
		pr_err("evmm: Failed to register misc device: %d\n", ret);
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
