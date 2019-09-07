//
// EVTCPServiceRequest.h
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

#include "Poco/Net/Net.h"
#include "Poco/Net/StreamSocket.h"
#include "Poco/NotificationQueue.h"

using Poco::Net::StreamSocket;

#ifndef POCO_EVNET_EVTCPSERVICEREQUEST_INCLUDED
#define POCO_EVNET_EVTCPSERVICEREQUEST_INCLUDED

namespace Poco{ namespace EVNet {
class EVTCPServiceRequest: public Notification
{
public:
	typedef enum {
		CONNECTION_REQUEST
		,DATA_SEND_REQUEST
		,DATA_RECEIVE_REQUEST
		,CLEANUP_REQUEST
	} what;
	EVTCPServiceRequest(what event, poco_socket_t acc_fd, Net::StreamSocket& ss);
	EVTCPServiceRequest(what event, poco_socket_t acc_fd, Net::StreamSocket& ss, Net::SocketAddress& addr);
	
	~EVTCPServiceRequest();

	poco_socket_t sockfd();

	poco_socket_t accSockfd();

	what getEvent();

	StreamSocket& getStreamSocket();

	Net::SocketAddress& getAddr();

private:
	what					_event;
	poco_socket_t			_acc_fd;
	Net::StreamSocket&		_ss;
	Net::SocketAddress		_addr;
};

inline EVTCPServiceRequest::what EVTCPServiceRequest::getEvent()
{
	return _event;
}

} } // namespace EVNet and Poco end.


#endif
