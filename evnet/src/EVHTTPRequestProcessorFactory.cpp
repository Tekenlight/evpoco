//
// EVHTTPRequestProcessorFactory.cpp
//
// Library: evnet
// Package: EVHTTPServer
// Module:  EVHTTPRequestProcessorFactory
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/evnet/EVHTTPRequestProcessorFactory.h"
#include "Poco/evnet/EVHTTPRequestProcessor.h"
#include "Poco/evnet/EVHTTPRequestHandlerFactory.h"
#include "Poco/evnet/EVServer.h"


namespace Poco {
namespace evnet {


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

EVProcessingState* EVHTTPRequestProcessorFactory::createCLProcState(EVServer * server)
{
	return new EVCommandLineProcessingState(server);
}

} } // namespace Poco::evnet
