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
	EVUpstreamEventNotification(poco_socket_t sockfd, what event, ssize_t bytes, int _errno = 0);
	EVUpstreamEventNotification(poco_socket_t sockfd, what event, size_t bytes, int _errno = 0);

	~EVUpstreamEventNotification();

	poco_socket_t sockfd();

	what getEvent();
	
	int getErrNo();

private:
	poco_socket_t			_sockfd;
	what					_event;
	int						_errno;
	ssize_t					_bytes;
};

inline EVUpstreamEventNotification::what EVUpstreamEventNotification::getEvent()
{
	return _event;
}

inline int EVUpstreamEventNotification::getErrNo()
{
	return _errno;
}

} } // namespace EVNet and Poco end.


#endif
