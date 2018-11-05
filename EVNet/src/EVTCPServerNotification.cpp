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

EVTCPServerNotification::EVTCPServerNotification(const StreamSocket& socket):
	_socket(socket)
{
	_closeerrorconn = false;
}

EVTCPServerNotification::EVTCPServerNotification(const StreamSocket& socket, bool closeConnInd):
	_socket(socket),
	_closeerrorconn(closeConnInd)
{
}

EVTCPServerNotification::~EVTCPServerNotification()
{
}

const StreamSocket& EVTCPServerNotification::socket() const
{
	return _socket;
}

bool EVTCPServerNotification::connInError()
{
	return _closeerrorconn;
}

} } // namespace EVNet and Poco end.
