//
// EVHTTPRequestProcessor.h
//
// Library: evnet
// Package: EVHTTPServer
// Module:  EVHTTPRequestProcessor
//
// Definition of the EVHTTPRequestProcessor class.
//
// Tekenlight Solutions Pvt Ltd.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#ifndef EVNet_EVHTTPRequestProcessor_INCLUDED
#define EVNet_EVHTTPRequestProcessor_INCLUDED

#include <chunked_memory_stream.h>

#include "Poco/Net/Net.h"
#include "Poco/evnet/evnet.h"
#include "Poco/evnet/EVTCPServerConnection.h"
#include "Poco/Net/HTTPResponse.h"
#include "Poco/evnet/EVServerSession.h"
#include "Poco/evnet/EVHTTPRequestHandlerFactory.h"
#include "Poco/evnet/EVHTTPServerResponseImpl.h"
#include "Poco/evnet/EVCLServerResponseImpl.h"
#include "Poco/evnet/EVCLServerRequestImpl.h"
#include "Poco/Net/HTTPServerParams.h"
#include "Poco/Mutex.h"
#include "Poco/evnet/EVProcessingState.h"
#include "Poco/evnet/EVHTTPProcessingState.h"
#include "Poco/evnet/EVCommandLineProcessingState.h"
#include "Poco/evnet/EVServerSession.h"

using Poco::Net::HTTPServerSession;
using Poco::Net::StreamSocket;
using Poco::Net::HTTPServerParams;
using Poco::Net::TCPServerParams;
using Poco::evnet::EVHTTPRequestHandlerFactory;
using Poco::Net::HTTPResponse;

namespace Poco {
namespace evnet {



class Net_API EVHTTPRequestProcessor: public EVTCPServerConnection
	/// This subclass of EVTCPServerConnection handles HTTP
	/// connections.
{
public:
	EVHTTPRequestProcessor(StreamSocket& socket, HTTPServerParams::Ptr pParams, EVHTTPRequestHandlerFactory::Ptr pFactory);
		/// Creates the EVHTTPRequestProcessor.

	EVHTTPRequestProcessor(StreamSocket& socket, HTTPServerParams::Ptr pParams, EVHTTPRequestHandlerFactory::Ptr pFactory, EVProcessingState * ReqProcState);
		/// Creates the EVHTTPRequestProcessor. For continuation of request processing on data being available on socket.

	virtual ~EVHTTPRequestProcessor();
		/// Destroys the EVHTTPRequestProcessor.
		
	void run();
		/// Handles all HTTP requests coming in.

	void procHTTPReq(EVHTTPProcessingState*);
		/// Handles HTTP requests coming, in an event driven way.
	
	void procWebSockReq(EVHTTPProcessingState*);
		/// Handles websocket requests coming, in an event driven way.
	
	void procCLReq(EVCommandLineProcessingState*);
		/// Handles CommandLine requests coming, in an event driven way.

protected:
	void sendErrorResponse(EVCLServerResponseImpl & response, HTTPResponse::HTTPStatus status);
	void sendErrorResponse(std::string http_version, EVServerSession& session,
				EVHTTPServerResponseImpl & response, HTTPResponse::HTTPStatus status);
	void sendErrorResponse(EVServerSession& session,
				EVHTTPServerResponseImpl & response, HTTPResponse::HTTPStatus status);
	void onServerStopped(const bool& abortCurrent);
	EVProcessingState * getProcState();
	void setProcState(EVProcessingState *s);

private:
	HTTPServerParams::Ptr         		_pParams;
	EVHTTPRequestHandlerFactory::Ptr	_pFactory;
	bool								_stopped;
	Poco::FastMutex						_mutex;
	EVProcessingState*					_reqProcState;
	chunked_memory_stream				*_mem_stream;
};


} } // namespace Poco::evnet


#endif // Net_EVHTTPServerConnection_INCLUDED
