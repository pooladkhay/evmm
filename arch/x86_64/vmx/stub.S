#include <linux/linkage.h>

/* not used yet */
.macro SAVE_GPRS
    push    %rax
    push    %rcx
    push    %rdx
    push    %rbx
    push    %rbp
    push    %rsi
    push    %rdi
    push    %r8
    push    %r9
    push    %r10
    push    %r11
    push    %r12
    push    %r13
    push    %r14
    push    %r15
.endm

/* not used yet */
.macro RESTORE_GRPS
    pop     %r15
    pop     %r14
    pop     %r13
    pop     %r12
    pop     %r11
    pop     %r10
    pop     %r9
    pop     %r8
    pop     %rdi
    pop     %rsi
    pop     %rbp
    pop     %rbx
    pop     %rdx
    pop     %rcx
    pop     %rax
.endm

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
 *   struct { ... } gprs;                // offset 64
 * };
 */

#define VCPU_VMCS_PHYS_ADDR 16
#define VCPU_ORIG_HOST_RSP  40
#define VCPU_HOST_RSP       56
#define VCPU_GPRS_OFFSET    64

/*
 * Offsets into struct evmm_vcpu.gprs
 * This reflects the order in which registers are defined
 */
#define GPRS_RAX    0
#define GPRS_RCX    8
#define GPRS_RDX    16
#define GPRS_RBX    24
#define GPRS_RSP    32
#define GPRS_RBP    40
#define GPRS_RSI    48
#define GPRS_RDI    56
#define GPRS_R8     64
#define GPRS_R9     72
#define GPRS_R10    80
#define GPRS_R11    88
#define GPRS_R12    96
#define GPRS_R13    104
#define GPRS_R14    112
#define GPRS_R15    120

#define VMCS_HOST_RSP 0x00006c14

.section .text

/*
 * int __vmx_vcpu_run(struct evmm_vcpu *vcpu)
 * 'struct evmm_vcpu *vcpu' is available in %rdi (first arg)
 */
SYM_FUNC_START(__vmx_vcpu_run)
    push    %rbp            /* callee saved */
    mov     %rsp, %rbp      /* creating a new frame */

    /* save callee-saved registers */
    push    %rbx
    push    %r12
    push    %r13
    push    %r14
    push    %r15

    mov     %rsp, VCPU_ORIG_HOST_RSP(%rdi)      /* save %rsp to pcpu->orig_host_rsp */

    /* TODO: investigate using scratch registers in VMCS */

    /* write vcpu* at the top of host_stack */
    mov     VCPU_HOST_RSP(%rdi), %rax
    sub     $8, %rax
    mov     %rdi, (%rax)
    mov     %rax, VCPU_HOST_RSP(%rdi)

    mov     $VMCS_HOST_RSP, %rdx
    vmwrite %rax, %rdx

    vmlaunch

    /* VMLAUNCH failed */

    /* calculate error code:
     * %rax = 1 (assume ZF set / VMfailValid)
     * %rcx = 2 (value for CF set / VMfailInvalid)
     * if CF=1, move %rcx into %rax.
     */
    mov     $1, %rax            /* default to error 1 (ZF set) */
    mov     $2, %rcx            /* prepare error 2 (CF set) */
    cmovc   %rcx, %rax          /* if CF=1, %rax becomes 2 */
    push    %rax                /* save the calculated error code to the stack */

    /* set vcpu.orig_host_rsp = NULL */
    xor     %rax, %rax
    mov     %rax, VCPU_ORIG_HOST_RSP(%rdi)

    /* remove vcpu from top of host_stack */
    mov     VCPU_HOST_RSP(%rdi), %rax
    add     $8, %rax
    mov     %rax, VCPU_HOST_RSP(%rdi)

    pop     %rax /* return value from vmlaunch */

    /* restore callee-saved registers */
    pop     %r15
    pop     %r14
    pop     %r13
    pop     %r12
    pop     %rbx
    pop     %rbp

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

    pop     %rdi                            /* %rdi now contains vcpu* */
    mov     VCPU_ORIG_HOST_RSP(%rdi), %rsp  /* restore the original stack that would return us to the ioctl call */

    /* restore callee-saved registers */
    pop     %r15
    pop     %r14
    pop     %r13
    pop     %r12
    pop     %rbx
    pop     %rbp

    /* return 0 from from '__vmx_vcpu_run' */
    xor %rax, %rax

    RET
SYM_CODE_END(__vmx_host_entrypoint)
