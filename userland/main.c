#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "../include/uapi/evmm.h"

int main(void)
{
	int evmm_fd;
	int ret;

	evmm_fd = open("/dev/evmm", O_RDWR);
	if (evmm_fd < 0) {
		fprintf(stderr, "failed to open /dev/evmm: %s\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	int evmm_api_version = 0;

	ret = ioctl(evmm_fd, EVMM_GET_API_VERSION, &evmm_api_version);
	if (ret < 0) {
		fprintf(stderr, "ioctl failed: %s\n", strerror(errno));
		close(evmm_fd);
		exit(EXIT_FAILURE);
	}

	printf("ioctl returned: %d\n", ret);
	printf("evmm api version: %d\n", evmm_api_version);
	printf("\n\n");

	int val = 0;
	ret = ioctl(evmm_fd, EVMM_VCPU_CREATE, &val);
	if (ret < 0) {
		fprintf(stderr, "ioctl failed: %s\n", strerror(errno));
		close(evmm_fd);
		exit(EXIT_FAILURE);
	}

	printf("ioctl returned: %d\n", ret);
	printf("val: %d\n", val);
	// this should fail with -ENOTTY
	// ret = ioctl(evmm_fd, 0, NULL);
	// if (ret >= 0) {
	// 	fprintf(stderr, "ioctl shouldn've succeeded: %s\n",
	// 		strerror(errno));
	// 	close(evmm_fd);
	// 	exit(EXIT_FAILURE);
	// }

	// printf("ioctl returned: %s, which was expected.\n", strerror(errno));

	if (close(evmm_fd) < 0) {
		fprintf(stderr, "failed to close device: %s\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}
