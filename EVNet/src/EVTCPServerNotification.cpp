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
	_socket(socket)
{
	_closeerrorconn = false;
}

EVTCPServerNotification::EVTCPServerNotification(StreamSocket& socket, bool closeConnInd):
	_socket(socket),
	_closeerrorconn(closeConnInd)
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

} } // namespace EVNet and Poco end.
