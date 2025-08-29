#include <linux/module.h>

static int __init evmm_init(void)
{
	pr_info("evmm_init.\n");
	return 0;
}

static void __exit evmm_exit(void)
{
	pr_info("evmm_exit.\n");
}

module_init(evmm_init);
module_exit(evmm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MJ Pooladkhay");
MODULE_DESCRIPTION("An experimental Virtual Machine Monitor");
