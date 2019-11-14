//
// EVHTTPServerSession.h
//
// Library: EVNet
// Package: EVHTTPServer
// Module:  EVHTTPServerSession
//
// Definition of the EVHTTPServerSession class.
//
// Copyright (c) 2018-2019, Tekenlight Solutions Pvt Ltd.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//



#include "Poco/EVNet/EVHTTPServerSession.h"

using Poco::Net::StreamSocket;
using Poco::Net::HTTPServerParams;

namespace Poco {
namespace EVNet {


EVHTTPServerSession::EVHTTPServerSession(const StreamSocket& socket, HTTPServerParams::Ptr pParams):HTTPServerSession(socket, pParams, true), _server(0)
{
}

EVHTTPServerSession::~EVHTTPServerSession()
{
	_mem_stream = 0;
}
				
bool EVHTTPServerSession::hasMoreRequests()
{
	return HTTPServerSession::hasMoreRequests();
}

int EVHTTPServerSession::receive(char* buffer, int length)
{
	return HTTPServerSession::receive(buffer, length);
}

EVServer* EVHTTPServerSession::getServer()
{
	return _server;
}

void EVHTTPServerSession::setServer(EVServer * server)
{
	_server = server;
}




} } // namespace Poco::EVNet


