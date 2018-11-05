//
// HTTPRequestHandlerFactory.cpp
//
// Library: Net
// Package: HTTPServer
// Module:  HTTPRequestHandlerFactory
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/Net/HTTPRequestHandlerFactory.h"


namespace Poco {
namespace Net {


HTTPRequestHandlerFactory::HTTPRequestHandlerFactory()
{
}


HTTPRequestHandlerFactory::~HTTPRequestHandlerFactory()
{
}

void HTTPRequestHandlerFactory::stopServer(const void * sender, const bool& ac)
{
	this->serverStopped(sender, ac);
	return ;
}


} } // namespace Poco::Net
