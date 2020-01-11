//
// EVTCPServerNotification.cpp
//
// Library: evnet
// Package: EVTCPServer
// Module:  EVTCPServer
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//

#include "Poco/evnet/EVTCPServerNotification.h"

using Poco::Net::StreamSocket;

namespace Poco{ namespace evnet {

/*
EVTCPServerNotification::EVTCPServerNotification(StreamSocket& socket):
	_socket(socket),
	_sockfd(socket.impl()->sockfd())
{
	_closeerrorconn = false;
}
*/

EVTCPServerNotification::EVTCPServerNotification(poco_socket_t sockfd, what event):
	_sockfd(sockfd),
	_event(event)
{
	//_closeerrorconn = false;
}

/*
EVTCPServerNotification::EVTCPServerNotification(poco_socket_t sockfd, bool closeConnInd):
	_closeerrorconn(closeConnInd),
	_sockfd(sockfd)
{
}
*/

EVTCPServerNotification::~EVTCPServerNotification()
{
}

/*
StreamSocket& EVTCPServerNotification::socket()
{
	return _socket;
}
*/

/*
bool EVTCPServerNotification::connInError()
{
	return _closeerrorconn;
}
*/

poco_socket_t EVTCPServerNotification::sockfd()
{
	return _sockfd;
}

} } // namespace evnet and Poco end.
