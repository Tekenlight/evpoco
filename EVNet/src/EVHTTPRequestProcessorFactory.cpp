//
// EVHTTPRequestProcessorFactory.cpp
//
// Library: EVNet
// Package: EVHTTPServer
// Module:  EVHTTPRequestProcessorFactory
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/EVNet/EVHTTPRequestProcessorFactory.h"
#include "Poco/EVNet/EVHTTPRequestProcessor.h"
#include "Poco/EVNet/EVHTTPRequestHandlerFactory.h"
#include "Poco/EVNet/EVServer.h"


namespace Poco {
namespace EVNet {


EVHTTPRequestProcessorFactory::EVHTTPRequestProcessorFactory(HTTPServerParams::Ptr pParams, EVHTTPRequestHandlerFactory::Ptr pFactory):
	_pParams(pParams),
	_pFactory(pFactory)
{
	poco_check_ptr (pFactory);
}


EVHTTPRequestProcessorFactory::~EVHTTPRequestProcessorFactory()
{
}


EVTCPServerConnection* EVHTTPRequestProcessorFactory::createConnection(StreamSocket& socket)
{
	return new EVHTTPRequestProcessor(socket, _pParams, _pFactory);
}

EVTCPServerConnection* EVHTTPRequestProcessorFactory::createConnection(StreamSocket& socket,
																	EVProcessingState * reqProcState)
{
	return new EVHTTPRequestProcessor(socket, _pParams, _pFactory, reqProcState);
}

EVProcessingState* EVHTTPRequestProcessorFactory::createReqProcState(EVServer * server)
{
	return new EVHTTPProcessingState(server);
}

} } // namespace Poco::EVNet
