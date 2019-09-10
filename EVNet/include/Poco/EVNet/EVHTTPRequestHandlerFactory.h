//
// EVHTTPRequestHandlerFactory.h
//
// Library: EVNet
// Package: EVHTTPServer
// Module:  EVHTTPRequestHandlerFactory
//
// Definition of the EVHTTPRequestHandlerFactory class.
//
// Copyright (c) 2019-2020, Tekenlight Solutions Pvt Ltd.
// and Contributors.
//
//


#ifndef EVNet_EVHTTPRequestHandlerFactory_INCLUDED
#define EVNet_EVHTTPRequestHandlerFactory_INCLUDED


#include "Poco/Net/Net.h"
#include "Poco/Net/HTTPServerRequest.h"
#include "Poco/Net/HTTPServerResponse.h"
#include "Poco/Net/HTTPRequestHandler.h"
#include "Poco/EVNet/EVHTTPRequestHandler.h"
#include "Poco/SharedPtr.h"
#include "Poco/BasicEvent.h"

using Poco::Net::HTTPServerRequest;
using Poco::Net::HTTPServerResponse;
using Poco::Net::HTTPRequestHandler;


namespace Poco {
namespace EVNet {

class Net_API EVHTTPRequestHandlerFactory
	/// A factory for EVHTTPRequestHandler objects.
	/// Subclasses must override the createRequestHandler()
	/// method.
{
public:
	typedef Poco::SharedPtr<EVHTTPRequestHandlerFactory> Ptr;
	
	EVHTTPRequestHandlerFactory();
		/// Creates the EVHTTPRequestHandlerFactory.

	virtual ~EVHTTPRequestHandlerFactory();
		/// Destroys the EVHTTPRequestHandlerFactory.

	virtual EVHTTPRequestHandler* createRequestHandler(const HTTPServerRequest& request) = 0;
		/// Must be overridden by subclasses.
		///
		/// Creates a new request handler for the given HTTP request.
		///
		/// The method should inspect the given HTTPServerRequest object (e.g., method
		/// and URI) and create an appropriate EVHTTPRequestHandler object to handle the
		/// request.
		///
		/// If the request contains a "Expect: 100-continue" header, it's possible
		/// to prevent the server from sending the default 100 Continue response 
		/// by setting the status of the response object that can be obtained through 
		/// the request object (request.response()) to something other than 200 OK.

	void stopServer(const void * sender, const bool& ac);
		/// This is somewhat of a hack to stop the threads running current conections.
		///
		/// Hack because, why should a factory object deal with events
		///
		/// Each Connection when started registers an event handler to process the event
		/// of server getting stopped.
		///
		/// This central caller has a collection of all those registered events.
		/// When the server gets stopped, each event is called in turn.

protected:
	Poco::BasicEvent<const bool> serverStopped;

private:
	EVHTTPRequestHandlerFactory(const EVHTTPRequestHandlerFactory&);
	EVHTTPRequestHandlerFactory& operator = (const EVHTTPRequestHandlerFactory&);
	
	friend class EVHTTPServer;
	friend class EVHTTPRequestProcessor;
};


} } // namespace Poco::EVNet


#endif // EVNet_EVHTTPRequestHandlerFactory_INCLUDED
