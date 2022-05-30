//
// EVHTTPRequestProcessorFactory.h
//
// Library: evnet
// Package: EVHTTPServer
// Module:  EVHTTPRequestProcessorFactory
//
// Definition of the EVHTTPRequestProcessorFactory class.
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#ifndef EVNet_EVHTTPRequestProcessorFactory_INCLUDED
#define EVNet_EVHTTPRequestProcessorFactory_INCLUDED


#include "Poco/Net/Net.h"
#include "Poco/evnet/EVTCPServerConnectionFactory.h"
#include "Poco/evnet/EVHTTPRequestHandlerFactory.h"
#include "Poco/Net/HTTPServerParams.h"
#include "Poco/evnet/EVHTTPProcessingState.h"
#include "Poco/evnet/EVCommandLineProcessingState.h"
#include "Poco/evnet/EVServer.h"

using Poco::Net::HTTPServerParams;
using Poco::Net::StreamSocket;

namespace Poco {
namespace evnet {


class Net_API EVHTTPRequestProcessorFactory: public EVTCPServerConnectionFactory
	/// This implementation of a EVTCPServerConnectionFactory
	/// is used by HTTPServer to create HTTPServerConnection objects.
{
public:
	EVHTTPRequestProcessorFactory(HTTPServerParams::Ptr pParams, EVHTTPRequestHandlerFactory::Ptr pFactory);
		/// Creates the EVHTTPRequestProcessorFactory.

	~EVHTTPRequestProcessorFactory();
		/// Destroys the EVHTTPRequestProcessorFactory.

	EVTCPServerConnection* createConnection(StreamSocket& socket);
		/// Creates an instance of HTTPServerConnection
		/// using the given StreamSocket.
	
	EVProcessingState* createReqProcState(EVServer *);
		/// Creates an instance of EVHTTPProcessingState

	EVProcessingState* createCLProcState(EVServer *);
		/// Creates an instance of EVCommandLineProcessingState

private:
	HTTPServerParams::Ptr          _pParams;
	EVHTTPRequestHandlerFactory::Ptr _pFactory;
};


} } // namespace Poco::evnet


#endif // EVNet_EVHTTPRequestProcessorFactory_INCLUDED
