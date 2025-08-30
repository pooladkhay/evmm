#include <linux/fs.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/printk.h>

long evmm_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg);

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

long evmm_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg)
{
	int r = 0; //-EINVAL;

	pr_info("ioctl called.\n");

	return r;
}

static int __init evmm_init(void)
{
	pr_info("evmm_init.\n");

	return misc_register(&evmm_dev);
}

static void __exit evmm_exit(void)
{
	pr_info("evmm_exit.\n");

	misc_deregister(&evmm_dev);
}

module_init(evmm_init);
module_exit(evmm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MJ Pooladkhay <mj@pooladkhay.com>");
MODULE_DESCRIPTION("An experimental Virtual Machine Monitor");
