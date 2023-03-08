//
// EVServerSession.h
//
// Library: evnet
// Package: EVHTTPServer
// Module:  EVServerSession
//
// Definition of the EVServerSession class.
//
// Tekenlight Solutions Pvt Ltd.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//



#include "Poco/evnet/EVServerSession.h"

using Poco::Net::StreamSocket;
using Poco::Net::HTTPServerParams;

namespace Poco {
namespace evnet {


EVServerSession::EVServerSession(const StreamSocket& socket, HTTPServerParams::Ptr pParams):HTTPServerSession(socket, pParams, true), _server(0)
{
}

EVServerSession::~EVServerSession()
{
	_mem_stream = 0;
}

EVServer* EVServerSession::getServer()
{
	return _server;
}

void EVServerSession::setServer(EVServer * server)
{
	_server = server;
}




} } // namespace Poco::evnet


