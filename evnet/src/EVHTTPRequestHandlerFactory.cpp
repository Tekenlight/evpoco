//
// EVHTTPRequestHandlerFactory.cpp
//
// Library: Net
// Package: HTTPServer
// Module:  EVHTTPRequestHandlerFactory
//
// Tekenlight Solutions Pvt Ltd.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/evnet/EVHTTPRequestHandlerFactory.h"


namespace Poco {
namespace evnet {


EVHTTPRequestHandlerFactory::EVHTTPRequestHandlerFactory()
{
}


EVHTTPRequestHandlerFactory::~EVHTTPRequestHandlerFactory()
{
}

void EVHTTPRequestHandlerFactory::stopServer(const void * sender, const bool& ac)
{
	this->serverStopped(sender, ac);
	return ;
}


} } // namespace Poco::evnet
