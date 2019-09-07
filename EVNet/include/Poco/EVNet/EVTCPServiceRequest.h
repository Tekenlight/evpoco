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
		DATA_FOR_READ_READY
		,REQDATA_CONSUMED
		,DATA_FOR_SEND_READY
		,ERROR_IN_PROCESSING
	} what;
	//EVTCPServiceRequest(StreamSocket& socket);
	EVTCPServiceRequest(poco_socket_t sockfd, what event);
	//EVTCPServiceRequest(poco_socket_t fd,  bool closeConnInd);
	
	~EVTCPServiceRequest();

	//StreamSocket& socket();
	poco_socket_t sockfd();

	what getEvent();

	//bool connInError();

private:
	//StreamSocket&			_socket;
	poco_socket_t			_sockfd;
	//bool					_closeerrorconn;
	what					_event;
};

inline EVTCPServiceRequest::what EVTCPServiceRequest::getEvent()
{
	return _event;
}

} } // namespace EVNet and Poco end.


#endif
