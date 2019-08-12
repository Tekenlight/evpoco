//
// EVHTTPServerStream.h
//
// Library: EVNet
// Package: EVHTTPServer
// Module:  EVHTTPServerStream
//
// Definition of the EVHTTPServerStream class.
//
// Copyright (c) 2018-2019, Tekenlight Solutions Pvt Ltd.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#ifndef EVNet_EVHTTPServerStream_INCLUDED
#define EVNet_EVHTTPServerStream_INCLUDED

#include <chunked_memory_stream.h>

#include "Poco/Net/Net.h"
#include "Poco/EVNet/EVNet.h"
#include "Poco/EVNet/EVTCPServerConnection.h"
#include "Poco/Net/HTTPResponse.h"
#include "Poco/EVNet/EVHTTPServerSession.h"
#include "Poco/EVNet/EVHTTPRequestHandlerFactory.h"
#include "Poco/EVNet/EVHTTPServerResponseImpl.h"
#include "Poco/Net/HTTPServerParams.h"
#include "Poco/Mutex.h"
#include "Poco/EVNet/EVProcessingState.h"
#include "Poco/EVNet/EVHTTPProcessingState.h"

using Poco::Net::HTTPServerSession;
using Poco::Net::StreamSocket;
using Poco::Net::HTTPServerParams;
using Poco::Net::TCPServerParams;
using Poco::EVNet::EVHTTPRequestHandlerFactory;
using Poco::Net::HTTPResponse;

namespace Poco {
namespace EVNet {



class Net_API EVHTTPServerStream: public EVTCPServerConnection
	/// This subclass of EVTCPServerConnection handles HTTP
	/// connections.
{
public:
	EVHTTPServerStream(StreamSocket& socket, HTTPServerParams::Ptr pParams, EVHTTPRequestHandlerFactory::Ptr pFactory);
		/// Creates the EVHTTPServerStream.

	EVHTTPServerStream(StreamSocket& socket, HTTPServerParams::Ptr pParams, EVHTTPRequestHandlerFactory::Ptr pFactory, EVProcessingState * ReqProcState);
		/// Creates the EVHTTPServerStream. For continuation of request processing on data being available on socket.

	virtual ~EVHTTPServerStream();
		/// Destroys the EVHTTPServerStream.
		
	void run();
		/// Handles all HTTP requests coming in.

	void evrun();
		/// Handles HTTP requests coming, in an event driven way.
	
protected:
	void sendErrorResponse(HTTPServerSession& session, HTTPResponse::HTTPStatus status);
	void onServerStopped(const bool& abortCurrent);
	EVProcessingState * getProcState();
	void setProcState(EVProcessingState *s);

private:
	HTTPServerParams::Ptr         		_pParams;
	EVHTTPRequestHandlerFactory::Ptr	_pFactory;
	bool								_stopped;
	Poco::FastMutex						_mutex;
	EVHTTPProcessingState*				_reqProcState;
	chunked_memory_stream				*_mem_stream;
};


} } // namespace Poco::EVNet


#endif // Net_EVHTTPServerConnection_INCLUDED
