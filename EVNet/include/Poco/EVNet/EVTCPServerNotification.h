//
// EVTCPServerNotification.h
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

#ifndef POCO_EVNET_EVTCPSERVERNOTIFICATION_INCLUDED
#define POCO_EVNET_EVTCPSERVERNOTIFICATION_INCLUDED

namespace Poco{ namespace EVNet {
class EVTCPServerNotification: public Notification
{
public:
	EVTCPServerNotification(const StreamSocket& socket);
	EVTCPServerNotification(const StreamSocket& socket, bool closeConnInd);
	
	~EVTCPServerNotification();

	const StreamSocket& socket() const;

	bool connInError();

private:
	StreamSocket _socket;
	bool _closeerrorconn;
};

} } // namespace EVNet and Poco end.


#endif
