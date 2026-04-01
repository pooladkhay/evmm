// #define DEBUG
#include <linux/atomic.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/preempt.h>
#include <linux/printk.h>
#include <linux/smp.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include "arch/x86_64/vmx/include/vcpu.h"
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
