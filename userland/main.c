#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

int main(void)
{
	int evmm_fd;
	int ret;

	evmm_fd = open("/dev/evmm", O_RDWR);
	if (evmm_fd < 0) {
		fprintf(stderr, "Failed to open /dev/evmm: %s\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	ret = ioctl(evmm_fd, 0 /* bad bad bad */, NULL);
	if (ret < 0) {
		fprintf(stderr, "ioctl failed: %s\n", strerror(errno));
		close(evmm_fd);
		exit(EXIT_FAILURE);
	}

	printf("ioctl returned: %d\n", ret);

	if (close(evmm_fd) < 0) {
		fprintf(stderr, "Failed to close device: %s\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}