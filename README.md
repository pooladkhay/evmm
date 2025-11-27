# eVMM

An experimental Virtual Machine Monitor (VMM).

eVMM is implemented as a Linux kernel module (lots of inspirations from KVM) with only one goal, that is learning virtualization concepts.

Current state:

- An IOCTL interface
- Support for Intel VT-x (VMX)
- External interrupts are caught and handled by the host kernel
- Entry and exits are done in an assembly stub for low-level control
- No EPT yet
