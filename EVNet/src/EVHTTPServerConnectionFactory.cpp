//
// EVHTTPServerConnectionFactory.cpp
//
// Library: EVNet
// Package: EVHTTPServer
// Module:  EVHTTPServerConnectionFactory
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/EVNet/EVHTTPServerConnectionFactory.h"
#include "Poco/EVNet/EVHTTPServerConnection.h"
#include "Poco/EVNet/EVHTTPRequestHandlerFactory.h"


namespace Poco {
namespace EVNet {


EVHTTPServerConnectionFactory::EVHTTPServerConnectionFactory(HTTPServerParams::Ptr pParams, EVHTTPRequestHandlerFactory::Ptr pFactory):
	_pParams(pParams),
	_pFactory(pFactory)
{
	poco_check_ptr (pFactory);
}


EVHTTPServerConnectionFactory::~EVHTTPServerConnectionFactory()
{
}


EVTCPServerConnection* EVHTTPServerConnectionFactory::createConnection(StreamSocket& socket)
{
	return new EVHTTPServerConnection(socket, _pParams, _pFactory);
}

EVTCPServerConnection* EVHTTPServerConnectionFactory::createConnection(StreamSocket& socket,
																	EVProcessingState * reqProcState)
{
	return new EVHTTPServerConnection(socket, _pParams, _pFactory, reqProcState);
}

EVProcessingState* EVHTTPServerConnectionFactory::createReaProcState()
{
	return new EVHTTPProcessingState();
}

} } // namespace Poco::EVNet
