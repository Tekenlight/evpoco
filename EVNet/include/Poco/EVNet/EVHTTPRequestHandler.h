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
	static const int INITIAL = 0;

	/* Return values of handleRequest method. */
	static const int PROCESSING_ERROR = -1;
	static const int PROCESSING = 0;
	static const int PROCESSING_COMPLETE = 1;

	EVHTTPRequestHandler();
		/// Creates the EVHTTPRequestHandler.

	virtual ~EVHTTPRequestHandler();
		/// Destroys the EVHTTPRequestHandler.

	virtual int handleRequest(Net::HTTPServerRequest& request, Net::HTTPServerResponse& response) = 0;
		/// Must be overridden by subclasses.
		///
		/// Handles the given request.

	int getState();
	void setState(int);
private:
	EVHTTPRequestHandler(const EVHTTPRequestHandler&);
	EVHTTPRequestHandler& operator = (const EVHTTPRequestHandler&);

	int	_state;
};


} } // namespace Poco::EVNet


#endif // Net_EVHTTPRequestHandler_INCLUDED
