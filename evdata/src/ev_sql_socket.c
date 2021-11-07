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

	if (fd_item.revents & POLLHUP) {
		printf("POLLHUP = [%X]\n", POLLHUP);
		printf("fd_item.revents & POLLHUP = [%X]\n", (fd_item.revents & POLLHUP));
		printf("SOCKET DISCONNECTD POLLHUP [%X]\n", fd);
		ret = 0;
	}
	else if (fd_item.revents & POLLERR) {
		printf("POLERR = [%X]\n", POLLERR);
		printf("fd_item.revents & POLLERR = [%X]\n", (fd_item.revents & POLLERR));
		printf("SOCKET ERROR POLLERR [%d]\n", fd);
		ret = 0;
	}
	else if (fd_item.revents & POLLNVAL) {
		printf("POLINVAL = [%X] revents = [%X]\n", POLLNVAL, fd_item.revents);
		printf("fd_item.revents & POLLNVAL = [%X]\n", (fd_item.revents & POLLNVAL));
		printf("SOCKET ERROR POLLNVAL [%d]\n", fd);
		ret = 0;
	}

	//printf("returning ret = [%d]\n", ret);

	return ret;
}
