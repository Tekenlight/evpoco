//
// EVTCPServerConnection.cpp
//
// Library: evnet
// Package: EVTCPServer
// Module:  EVTCPServerConnection
//
// Tekenlight Solutions Pvt Ltd.
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

/*
 * HTTP2 enhancement 
 * new constructor may be required to create this object
 * without a connection
 */


EVTCPServerConnection::EVTCPServerConnection(StreamSocket& socket):
	_socket(socket)
{
}

EVTCPServerConnection::EVTCPServerConnection(EVAcceptedStreamSocket* tn):
	_socket(tn->getStreamSocket()),
	_tn(tn)
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
