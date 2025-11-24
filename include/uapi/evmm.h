#ifndef EVMM_H
#define EVMM_H

#include <linux/ioctl.h>

/* 0xEA in not in use:
 * https://docs.kernel.org/userspace-api/ioctl/ioctl-number.html
 */
#define EVMMIO 0xEA

/*
 * ioctls for /dev/evmm fds:
 */
#define EVMM_GET_API_VERSION _IOR(EVMMIO, 0x00, int)
#define EVMM_VM_CREATE _IOR(EVMMIO, 0x01, int)
#define EVMM_VCPU_CREATE _IOR(EVMMIO, 0x02, int)
#define EVMM_VCPU_RUN _IO(EVMMIO, 0x03)

#endif
