#include <linux/linkage.h>

/*
 * Offsets into struct evmm_vcpu
 * Defined in 'arch/x86_64/vmx/vmx.h'
 *
 * struct evmm_vcpu {
 *   void *guest_stack;                  // offset 0
 *	 struct evmm_vmcs *vmcs_region;      // offset 8
 *   phys_addr_t vmcs_region_phys;       // offset 16
 *   void *msr_bitmap;                   // offset 24
 *   phys_addr_t msr_bitmap_phys;        // offset 32
 *   void *orig_host_rsp;                // offset 40
 *   void *host_stack;                   // offset 48
 *	 void *host_rsp;	                 // offset 56
 *	 u64 launched;                       // offset 64
 *   struct {
 *       __u64 rax, rcx, rdx, rbx;
 * 		 __u64 rbp, rsi, rdi;            // rsp is ignored
 * 		 __u64 r8, r9, r10, r11;
 * 		 __u64 r12, r13, r14, r15;
 *   } gprs;                             // offset 72
 * };
 */

#define VCPU_VMCS_PHYS_ADDR 16
#define VCPU_ORIG_HOST_RSP  40
#define VCPU_HOST_RSP       56
#define VCPU_LAUNCHED       64
#define VCPU_GPRS_OFFSET    72

/*
 * Offsets into struct evmm_vcpu.gprs
 * This reflects the order in which registers are defined
 */
#define GPRS_RAX    (0 + VCPU_GPRS_OFFSET)
#define GPRS_RCX    (8 + VCPU_GPRS_OFFSET)
#define GPRS_RDX    (16 + VCPU_GPRS_OFFSET)
#define GPRS_RBX    (24 + VCPU_GPRS_OFFSET)
#define GPRS_RBP    (32 + VCPU_GPRS_OFFSET)
#define GPRS_RSI    (40 + VCPU_GPRS_OFFSET)
#define GPRS_RDI    (48 + VCPU_GPRS_OFFSET)
#define GPRS_R8     (56 + VCPU_GPRS_OFFSET)
#define GPRS_R9     (64 + VCPU_GPRS_OFFSET)
#define GPRS_R10    (72 + VCPU_GPRS_OFFSET)
#define GPRS_R11    (80 + VCPU_GPRS_OFFSET)
#define GPRS_R12    (88 + VCPU_GPRS_OFFSET)
#define GPRS_R13    (96 + VCPU_GPRS_OFFSET)
#define GPRS_R14    (104 + VCPU_GPRS_OFFSET)
#define GPRS_R15    (112 + VCPU_GPRS_OFFSET)

#define VMCS_HOST_RSP 0x00006c14

.macro RESTORE_GUEST_GPRS
    movq    GPRS_RAX(%rdi), %rax
    movq    GPRS_RCX(%rdi), %rcx
    movq    GPRS_RDX(%rdi), %rdx
    movq    GPRS_RBX(%rdi), %rbx
    movq    GPRS_RBP(%rdi), %rbp
    movq    GPRS_R8(%rdi), %r8
    movq    GPRS_R9(%rdi), %r9
    movq    GPRS_R10(%rdi), %r10
    movq    GPRS_R11(%rdi), %r11
    movq    GPRS_R12(%rdi), %r12
    movq    GPRS_R13(%rdi), %r13
    movq    GPRS_R14(%rdi), %r14
    movq    GPRS_R15(%rdi), %r15
    movq    GPRS_RSI(%rdi), %rsi
    movq    GPRS_RDI(%rdi), %rdi
.endm

.section .text

/*
 * int __vmx_vcpu_run(struct evmm_vcpu *vcpu)
 * 'struct evmm_vcpu *vcpu' is available in %rdi (first arg)
 */
SYM_FUNC_START(__vmx_vcpu_run)
    pushq    %rbp            /* callee saved */
    movq     %rsp, %rbp      /* creating a new frame */

    /* save callee-saved registers */
    pushq    %rbx
    pushq    %r12
    pushq    %r13
    pushq    %r14
    pushq    %r15

    movq     %rsp, VCPU_ORIG_HOST_RSP(%rdi)      /* save %rsp to vcpu.orig_host_rsp */

    /*
     * will be used in entry_failed path.
     * since %rsp is already saved, we
     * never need to pop this upon restore.
     */
    pushq   %rdi

    /* write vcpu* at the top of host_stack */
    movq     VCPU_HOST_RSP(%rdi), %rax
    subq     $8, %rax
    movq     %rdi, (%rax)
    movq     %rax, VCPU_HOST_RSP(%rdi)

    /* update HOST_RSP in VMCS */
    movq     $VMCS_HOST_RSP, %rdx
    vmwrite  %rax, %rdx

    movq    VCPU_LAUNCHED(%rdi), %rax
    testq   %rax, %rax
    jnz    resume_path

    RESTORE_GUEST_GPRS

    vmlaunch

    jmp     entry_failed

resume_path:
    RESTORE_GUEST_GPRS
    vmresume

entry_failed:
    /* VMLAUNCH/VMRESUME failed */

    popq %rdi

    /* calculate error code:
     * %rax = 1 (assume ZF set / VMfailValid)
     * %rcx = 2 (value for CF set / VMfailInvalid)
     * if CF=1, move %rcx into %rax.
     */
    movq     $1, %rax            /* default to error 1 (ZF set) */
    movq     $2, %rcx            /* prepare error 2 (CF set) */
    cmovcq   %rcx, %rax          /* if CF=1, %rax becomes 2 */
    pushq    %rax                /* save the calculated error code to the stack */

    /* set vcpu.orig_host_rsp = NULL */
    xorl     %eax, %eax
    movq     %rax, VCPU_ORIG_HOST_RSP(%rdi)

    /* remove vcpu from top of host_stack */
    movq     VCPU_HOST_RSP(%rdi), %rax
    addq     $8, %rax
    movq     %rax, VCPU_HOST_RSP(%rdi)

    popq     %rax /* return value from vmlaunch/vmresume */

    /* restore callee-saved registers */
    popq     %r15
    popq     %r14
    popq     %r13
    popq     %r12
    popq     %rbx
    popq     %rbp

    RET
SYM_FUNC_END(__vmx_vcpu_run)

/*
 * void __vmx_host_entrypoint(void)
 * 'struct evmm_vcpu *vcpu' is available on the stack
 */
SYM_CODE_START(__vmx_host_entrypoint)
    /*
     * IBT Requirement
     * Since we take the address of this label in C, it is an "Indirect Target".
     * We MUST start with ENDBR to prevent a #CP exception on IBT-enabled hardware.
     */
    ENDBR

    /* save guest rdi on the stack */
    pushq    %rdi
    /* %rdi now contains vcpu* */
    movq     8(%rsp), %rdi

    /* save all guest GPRs to vcpu struct, except for rdi */
    movq    %rax, GPRS_RAX(%rdi)
    movq    %rcx, GPRS_RCX(%rdi)
    movq    %rdx, GPRS_RDX(%rdi)
    movq    %rbx, GPRS_RBX(%rdi)
    movq    %rbp, GPRS_RBP(%rdi)
    movq    %rsi, GPRS_RSI(%rdi)
    movq    %r8, GPRS_R8(%rdi)
    movq    %r9, GPRS_R9(%rdi)
    movq    %r10, GPRS_R10(%rdi)
    movq    %r11, GPRS_R11(%rdi)
    movq    %r12, GPRS_R12(%rdi)
    movq    %r13, GPRS_R13(%rdi)
    movq    %r14, GPRS_R14(%rdi)
    movq    %r15, GPRS_R15(%rdi)

    /* mark vcpu as launched */
    movq    $1, VCPU_LAUNCHED(%rdi)

    /* save the original stack that would return us to the ioctl call, to rcx */
    movq    VCPU_ORIG_HOST_RSP(%rdi), %rcx

    /* save guest rdi to vmcs */
    popq    %rax
    movq    %rax, GPRS_RDI(%rdi)

    /* after this, vcpu->host_stack is clear, i.e. does not contain any values. next launch/resume will populate it again */
    addq    $8, %rsp
    movq    %rsp, VCPU_HOST_RSP(%rdi)

    /* restore the original stack that would return us to the ioctl call */
    movq    %rcx, %rsp

    /* restore callee-saved registers */
    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %rbx
    popq    %rbp

    /* return 0 from from '__vmx_vcpu_run' */
    xorl    %eax, %eax

    RET
SYM_CODE_END(__vmx_host_entrypoint)
