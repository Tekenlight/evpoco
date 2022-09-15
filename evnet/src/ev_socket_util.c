#include <stdio.h>
#include <poll.h>
#include <errno.h>
#include <string.h>

int socket_live(int fd)
{
	int time_out = 0;

	struct pollfd fd_item;
	memset(&fd_item, 0, sizeof(struct pollfd));

	fd_item.fd = fd;
	fd_item.events = POLLIN | POLLOUT | POLLERR;

	int ret = poll(&fd_item, 1, time_out);

	//printf("ret = [%d] orig_fd = [%d] fd = [%d] revents = [%00X]\n", ret, fd, fd_item.fd, fd_item.revents);
	if (ret < 0) {
		printf("%s\n", strerror(errno));
		return 0;
	}

	// Basically, upon timeout return OK. as we are not waiting at all.
	// As such if there are any errors we will return 0
	if (ret == 0) ret = 1;

	if (fd_item.revents & POLLHUP) {
		printf("[%s:%d] POLLHUP = [%X]\n", __FILE__, __LINE__, POLLHUP);
		printf("[%s:%d] fd_item.revents & POLLHUP = [%X]\n", __FILE__, __LINE__, (fd_item.revents & POLLHUP));
		printf("[%s:%d] SOCKET DISCONNECTD POLLHUP [%X]\n", __FILE__, __LINE__, fd);
		ret = 0;
	}
	else if (fd_item.revents & POLLERR) {
		printf("[%s:%d] POLERR = [%X]\n", __FILE__, __LINE__, POLLERR);
		printf("[%s:%d] fd_item.revents & POLLERR = [%X]\n", __FILE__, __LINE__, (fd_item.revents & POLLERR));
		printf("[%s:%d] SOCKET ERROR POLLERR [%d]\n", __FILE__, __LINE__, fd);
		ret = 0;
	}
	else if (fd_item.revents & POLLNVAL) {
		printf("[%s:%d] POLINVAL = [%X] revents = [%X]\n", __FILE__, __LINE__, POLLNVAL, fd_item.revents);
		printf("[%s:%d] fd_item.revents & POLLNVAL = [%X]\n", __FILE__, __LINE__, (fd_item.revents & POLLNVAL));
		printf("[%s:%d] SOCKET ERROR POLLNVAL [%d]\n", __FILE__, __LINE__, fd);
		ret = 0;
	}

	//printf("returning ret = [%d]\n", ret);

	return ret;
}
