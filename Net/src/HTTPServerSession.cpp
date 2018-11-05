//
// HTTPServerSession.cpp
//
// Library: Net
// Package: HTTPServer
// Module:  HTTPServerSession
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include <iostream>
#include "Poco/Net/HTTPServerSession.h"


namespace Poco {
namespace Net {


HTTPServerSession::HTTPServerSession(const StreamSocket& socket, HTTPServerParams::Ptr pParams):
	HTTPSession(socket, pParams->getKeepAlive()),
	_firstRequest(true),
	_keepAliveTimeout(pParams->getKeepAliveTimeout()),
	_maxKeepAliveRequests(pParams->getMaxKeepAliveRequests())
{
	setTimeout(pParams->getTimeout());
	this->socket().setReceiveTimeout(pParams->getTimeout());
}


HTTPServerSession::~HTTPServerSession()
{
}


bool HTTPServerSession::hasMoreRequests()
{
	if (!socket().impl()->initialized()) return false;

	if (_firstRequest)
	{
		_firstRequest = false;
		// This is to fix the bug of boundary condition defensive code.
		if (0 >= _maxKeepAliveRequests) _maxKeepAliveRequests = 1;
		--_maxKeepAliveRequests;
		/* getTimeout is Receive time out where as _keepAliveTimeout is the amount of time server
		 * has to keep alive waiting for a subsequent request */
		return socket().poll(getTimeout(), Socket::SELECT_READ);
	}
	//else if (_maxKeepAliveRequests != 0 && getKeepAlive()) // This is a bug The fix is to make the code defensive.
	else if (_maxKeepAliveRequests > 0 && getKeepAlive())
	{
		// getKeepAlive is from params the above checks can keep alive and whether to keep alive
		if (_maxKeepAliveRequests > 0) 
			--_maxKeepAliveRequests;
		/* getTimeout is Receive time out where as _keepAliveTimeout is the amount of time server
		 * has to keep alive without any additional requests */
		return buffered() > 0 || socket().poll(_keepAliveTimeout, Socket::SELECT_READ);
	}
	else return false;
}


SocketAddress HTTPServerSession::clientAddress()
{
	return socket().peerAddress();
}


SocketAddress HTTPServerSession::serverAddress()
{
	return socket().address();
}


} } // namespace Poco::Net
