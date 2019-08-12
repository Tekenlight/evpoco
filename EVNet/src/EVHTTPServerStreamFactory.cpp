//
// EVHTTPServerStreamFactory.cpp
//
// Library: EVNet
// Package: EVHTTPServer
// Module:  EVHTTPServerStreamFactory
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/EVNet/EVHTTPServerStreamFactory.h"
#include "Poco/EVNet/EVHTTPServerStream.h"
#include "Poco/EVNet/EVHTTPRequestHandlerFactory.h"


namespace Poco {
namespace EVNet {


EVHTTPServerStreamFactory::EVHTTPServerStreamFactory(HTTPServerParams::Ptr pParams, EVHTTPRequestHandlerFactory::Ptr pFactory):
	_pParams(pParams),
	_pFactory(pFactory)
{
	poco_check_ptr (pFactory);
}


EVHTTPServerStreamFactory::~EVHTTPServerStreamFactory()
{
}


EVTCPServerConnection* EVHTTPServerStreamFactory::createConnection(StreamSocket& socket)
{
	return new EVHTTPServerStream(socket, _pParams, _pFactory);
}

EVTCPServerConnection* EVHTTPServerStreamFactory::createConnection(StreamSocket& socket,
																	EVProcessingState * reqProcState)
{
	return new EVHTTPServerStream(socket, _pParams, _pFactory, reqProcState);
}

EVProcessingState* EVHTTPServerStreamFactory::createReaProcState()
{
	return new EVHTTPProcessingState();
}

} } // namespace Poco::EVNet
