//
// EVHTTPRequestHandlerFactory.cpp
//
// Library: Net
// Package: HTTPServer
// Module:  EVHTTPRequestHandlerFactory
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
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
