//
// EVUpstreamEventNotification.cpp
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

#include "Poco/EVNet/EVUpstreamEventNotification.h"

namespace Poco{ namespace EVNet {

EVUpstreamEventNotification::EVUpstreamEventNotification(poco_socket_t sockfd, what event, ssize_t bytes, int _errno):
	_sockfd(sockfd),
	_event(event),
	_bytes(bytes)
{
}

EVUpstreamEventNotification::EVUpstreamEventNotification(poco_socket_t sockfd, what event, size_t bytes, int _errno):
	_sockfd(sockfd),
	_event(event),
	_bytes(bytes)
{
}


EVUpstreamEventNotification::~EVUpstreamEventNotification()
{
}

poco_socket_t EVUpstreamEventNotification::sockfd()
{
	return _sockfd;
}

} } // namespace EVNet and Poco end.
