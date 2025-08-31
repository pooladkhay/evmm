#include <linux/ioctl.h>

#define EVMM_API_VERSION 1

/* 0xEA in not in use:
 * https://docs.kernel.org/userspace-api/ioctl/ioctl-number.html */
#define EVMMIO 0xEA

/*
 * ioctls for /dev/evmm fds:
 */
#define EVMM_GET_API_VERSION _IOR(EVMMIO, 0x00, int)
