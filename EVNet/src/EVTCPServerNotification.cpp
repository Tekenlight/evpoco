//
// EVTCPServerNotification.cpp
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

#include "Poco/EVNet/EVTCPServerNotification.h"

using Poco::Net::StreamSocket;

namespace Poco{ namespace EVNet {

EVTCPServerNotification::EVTCPServerNotification(StreamSocket& socket):
	_socket(socket),
	_sockfd(socket.impl()->sockfd())
{
	_closeerrorconn = false;
}
EVTCPServerNotification::EVTCPServerNotification(StreamSocket& socket, poco_socket_t sockfd):
	_socket(socket),
	_sockfd(sockfd)
{
	_closeerrorconn = false;
}

EVTCPServerNotification::EVTCPServerNotification(StreamSocket& socket, poco_socket_t sockfd, bool closeConnInd):
	_socket(socket),
	_closeerrorconn(closeConnInd),
	_sockfd(sockfd)
{
}

EVTCPServerNotification::~EVTCPServerNotification()
{
}

StreamSocket& EVTCPServerNotification::socket()
{
	return _socket;
}

bool EVTCPServerNotification::connInError()
{
	return _closeerrorconn;
}

poco_socket_t EVTCPServerNotification::sockfd()
{
	return _sockfd;
}

} } // namespace EVNet and Poco end.
