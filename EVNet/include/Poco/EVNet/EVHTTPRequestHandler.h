//
// EVHTTPRequestHandler.h
//
// Library: EVNet
// Package: EVHTTPServer
// Module:  EVHTTPRequestHandler
//
// Definition of the EVHTTPRequestHandler class.
//
// Copyright (c) 2019-2020, Tekenlight Solutions Pvt Ltd
// and Contributors.
//
//


#ifndef Net_EVHTTPRequestHandler_INCLUDED
#define Net_EVHTTPRequestHandler_INCLUDED


#include "Poco/Net/Net.h"
#include "Poco/Net/HTTPRequestHandler.h"
#include "Poco/EVNet/EVNet.h"


namespace Poco {
namespace EVNet {

class Net_API EVHTTPRequestHandler
	/// The abstract base class for EVHTTPRequestHandlers 
	/// created by EVHTTPServer.
	///
	/// Derived classes must override the handleRequest() method.
	/// Furthermore, a EVHTTPRequestHandlerFactory must be provided.
	///
	/// The handleRequest() method must perform the complete handling
	/// of the HTTP request connection. As soon as the handleRequest() 
	/// method returns, the request handler object is destroyed.
	///
	/// A new EVHTTPRequestHandler object will be created for
	/// each new HTTP request that is received by the HTTPServer.
{
public:
	typedef enum {
		 INITIAL
		,IN_PROGRESS
		,WAITING_FOR_DATA
		,COMPLETE
	} req_proc_state;

	/* Return values of handleRequest method. */
	static const int PROCESSING_ERROR = -1;
	static const int PROCESSING_COMPLETE = 1;
	static const int NEED_MORE_DATA = 0;

	EVHTTPRequestHandler();
		/// Creates the EVHTTPRequestHandler.

	virtual ~EVHTTPRequestHandler();
		/// Destroys the EVHTTPRequestHandler.

	virtual int handleRequest(Net::HTTPServerRequest& request, Net::HTTPServerResponse& response) = 0;
		/// Must be overridden by subclasses.
		///
		/// Handles the given request.

	req_proc_state getState();
	void setState(req_proc_state);
private:
	EVHTTPRequestHandler(const EVHTTPRequestHandler&);
	EVHTTPRequestHandler& operator = (const EVHTTPRequestHandler&);

	req_proc_state	_state;
};


} } // namespace Poco::EVNet


#endif // Net_EVHTTPRequestHandler_INCLUDED
