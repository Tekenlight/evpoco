//
// EVHTTPServerConnection.h
//
// Library: EVNet
// Package: EVHTTPServer
// Module:  EVHTTPServerConnection
//
// Definition of the EVHTTPServerConnection class.
//
// Copyright (c) 2018-2019, Tekenlight Solutions Pvt Ltd.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#ifndef EVNet_EVHTTPServerConnection_INCLUDED
#define EVNet_EVHTTPServerConnection_INCLUDED


#include "Poco/Net/Net.h"
#include "Poco/Net/TCPServerConnection.h"
#include "Poco/Net/HTTPResponse.h"
#include "Poco/Net/HTTPServerSession.h"
#include "Poco/EVNet/EVHTTPRequestHandlerFactory.h"
#include "Poco/Net/HTTPServerParams.h"
#include "Poco/Mutex.h"

using Poco::Net::HTTPServerSession;
using Poco::Net::TCPServerConnection;
using Poco::Net::StreamSocket;
using Poco::Net::HTTPServerParams;
using Poco::Net::TCPServerParams;
using Poco::EVNet::EVHTTPRequestHandlerFactory;
using Poco::Net::HTTPResponse;

namespace Poco {
namespace EVNet {




class Net_API EVHTTPServerConnection: public TCPServerConnection
	/// This subclass of TCPServerConnection handles HTTP
	/// connections.
{
public:
	EVHTTPServerConnection(const StreamSocket& socket, HTTPServerParams::Ptr pParams, EVHTTPRequestHandlerFactory::Ptr pFactory);
		/// Creates the EVHTTPServerConnection.

	virtual ~EVHTTPServerConnection();
		/// Destroys the EVHTTPServerConnection.
		
	void run();
		/// Handles all HTTP requests coming in.

protected:
	void sendErrorResponse(HTTPServerSession& session, HTTPResponse::HTTPStatus status);
	void onServerStopped(const bool& abortCurrent);

private:
	HTTPServerParams::Ptr          _pParams;
	EVHTTPRequestHandlerFactory::Ptr _pFactory;
	bool _stopped;
	Poco::FastMutex _mutex;
};


} } // namespace Poco::EVNet


#endif // Net_EVHTTPServerConnection_INCLUDED
