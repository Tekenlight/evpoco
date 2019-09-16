//
// EVUpstreamEventNotification.h
//
// Library: EVNet
// Package: EVTCPServer
// Module:  EVTCPServer
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//

#include <errno.h>
#include "Poco/Net/Net.h"
#include "Poco/EVNet/EVNet.h"
#include "Poco/Net/StreamSocket.h"
#include "Poco/NotificationQueue.h"

#ifndef POCO_EVNET_EVUPSTREAMEVENTNOTIFICATION_INCLUDED
#define POCO_EVNET_EVUPSTREAMEVENTNOTIFICATION_INCLUDED

namespace Poco{ namespace EVNet {

class EVUpstreamEventNotification: public Notification
{
public:
	typedef enum {
		SOCKET_CONNECTED=0
		,DATA_RECEIVED
		,DATA_SENT
		,ERROR
	} what;
	EVUpstreamEventNotification(poco_socket_t sockfd, what event, int cb_evid_num, ssize_t bytes, int err_no = 0);
	EVUpstreamEventNotification(poco_socket_t sockfd, what event, int cb_evid_num, size_t bytes, int err_no = 0);
	EVUpstreamEventNotification(poco_socket_t sockfd, what event, int cb_evid_num, int bytes, int err_no = 0);

	~EVUpstreamEventNotification();

	poco_socket_t sockfd();

	what getEvent();
	
	int getErrNo();

	ssize_t getBytes();

	int getCBEVIDNum();

	void debug(const char* file, const int lineno);

private:
	poco_socket_t			_sockfd;
	what					_event;
	int						_errno;
	ssize_t					_bytes;
	int						_cb_evid_num;
};

inline EVUpstreamEventNotification::what EVUpstreamEventNotification::getEvent()
{
	return _event;
}

inline int EVUpstreamEventNotification::getErrNo()
{
	return _errno;
}

inline ssize_t EVUpstreamEventNotification::getBytes()
{
	return _bytes;
}

inline int EVUpstreamEventNotification::getCBEVIDNum()
{
	return _cb_evid_num;
}

inline void EVUpstreamEventNotification::debug(const char* file, const int lineno)
{
	printf("[%p][%s:%d] _sockfd = %d\n", pthread_self(), file, lineno, _sockfd);
	printf("[%p][%s:%d] _event = %d\n", pthread_self(), file, lineno, _event);
	printf("[%p][%s:%d] _bytes = %zd\n", pthread_self(), file, lineno, _bytes);
	printf("[%p][%s:%d] _cb_evid_num = %d\n", pthread_self(), file, lineno, _cb_evid_num);
	printf("[%p][%s:%d] _errno = %d\n", pthread_self(), file, lineno, _errno);
}

} } // namespace EVNet and Poco end.


#endif