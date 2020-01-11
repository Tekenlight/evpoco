//
// EVTCPServerConnection.cpp
//
// Library: evnet
// Package: EVTCPServer
// Module:  EVTCPServerConnection
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/evnet/EVTCPServerConnection.h"
#include "Poco/Exception.h"
#include "Poco/ErrorHandler.h"


using Poco::Exception;
using Poco::ErrorHandler;


namespace Poco {
namespace evnet {


EVTCPServerConnection::EVTCPServerConnection(StreamSocket& socket):
	_socket(socket)
{
}


EVTCPServerConnection::~EVTCPServerConnection()
{
}


void EVTCPServerConnection::start(bool throwExcp)
{
	run();
}
void EVTCPServerConnection::start()
{
	try
	{
		run();
	}
	catch (Exception& exc)
	{
		ErrorHandler::handle(exc);
		throw;
	}
	catch (std::exception& exc)
	{
		ErrorHandler::handle(exc);
		throw;
	}
	catch (...)
	{
		ErrorHandler::handle();
		throw;
	}
}


} } // namespace Poco::evnet
