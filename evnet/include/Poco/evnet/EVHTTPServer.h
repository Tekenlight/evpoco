//
// EVHTTPServer.h
//
// Library: evnet
// Package: EVHTTPServer
// Module:  EVHTTPServer
//
// Definition of the EVHTTPServer class.
//
// Tekenlight Solutions Pvt Ltd.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#ifndef EVNet_EVHTTPServer_INCLUDED
#define EVNet_EVHTTPServer_INCLUDED


#include "Poco/Net/Net.h"
#include "Poco/evnet/EVTCPServer.h"
#include "Poco/evnet/EVHTTPRequestHandlerFactory.h"
#include "Poco/Net/HTTPServerParams.h"
#include "Poco/evnet/EVHTTPRequestProcessorFactory.h"

using Poco::Net::HTTPServerParams;
using Poco::Net::ServerSocket;
using Poco::evnet::EVHTTPRequestProcessorFactory;


namespace Poco {
namespace evnet {


class Net_API EVHTTPServer
	/// A class that implements afull-featured multithreaded HTTP server.
	/// Uses a TCP server from within. favoring inclusion over inheritence.
	/// This design pattern will allow changes within the module without
	/// affecting the interface.
	///
	/// A EVHTTPRequestHandlerFactory must be supplied.
	/// The ServerSocket must be bound and in listening state.
	///
	/// To configure various aspects of the server, a HTTPServerParams
	/// object can be passed to the constructor.
	///
	/// The server supports:
	///   - HTTP/1.0 and HTTP/1.1
	///   - automatic handling of persistent connections.
	///   - automatic decoding/encoding of request/response message bodies
	///     using chunked transfer encoding.
	///
	/// Please see the EVTCPServer class for information about
	/// connection and thread handling.
	///
	/// See RFC 2616 <http://www.faqs.org/rfcs/rfc2616.html> for more
	/// information about the HTTP protocol.
{
public:
	EVHTTPServer(EVHTTPRequestHandlerFactory::Ptr pFactory, Poco::UInt16 portNumber = 80, HTTPServerParams::Ptr pParams = new HTTPServerParams);
		/// Creates EVHTTPServer listening on the given port (default 80).
		///
		/// The server takes ownership of the HTTPRequstHandlerFactory
		/// and deletes it when it's no longer needed.
		///
		/// New threads are taken from the default thread pool.

	EVHTTPServer(EVHTTPRequestHandlerFactory::Ptr pFactory, const ServerSocket& socket, HTTPServerParams::Ptr pParams);
		/// Creates the EVHTTPServer, using the given ServerSocket.
		///
		/// The server takes ownership of the HTTPRequstHandlerFactory
		/// and deletes it when it's no longer needed.
		///
		/// The server also takes ownership of the HTTPServerParams object.
		///
		/// New threads are taken from the default thread pool.

	EVHTTPServer(EVHTTPRequestHandlerFactory::Ptr pFactory, Poco::ThreadPool& threadPool, const ServerSocket& socket, HTTPServerParams::Ptr pParams);
		/// Creates the EVHTTPServer, using the given ServerSocket.
		///
		/// The server takes ownership of the HTTPRequstHandlerFactory
		/// and deletes it when it's no longer needed.
		///
		/// The server also takes ownership of the HTTPServerParams object.
		///
		/// New threads are taken from the given thread pool.

	EVHTTPServer(EVHTTPRequestHandlerFactory::Ptr pFactory, int pipe_rd_fd, int pipe_wr_fd,  HTTPServerParams::Ptr pParams);
		/// Creates the EVHTTPServer, using the given read end of the IPC-pipe.
		///
		/// The server takes ownership of the HTTPRequstHandlerFactory
		/// and deletes it when it's no longer needed.
		///
		/// The server also takes ownership of the HTTPServerParams object.
		///
		/// New threads are taken from the default thread pool.

	~EVHTTPServer();
		/// Destroys the EVHTTPServer and its EVHTTPRequestHandlerFactory.

	void start();
		/// Starts the server. A new thread will be
		/// created that waits for and accepts incoming
		/// connections.
		///
		/// Before start() is called, the ServerSocket passed to
		/// EVHTTPServer  must have been bound and put into listening state.

	void stop();
		/// Stops the server.
		///
		/// No new connections will be accepted.
		/// Already handled connections will continue to be served.
		///
		/// Once the server has been stopped, it cannot be restarted.
		
	void stopAll(bool abortCurrent = false);
		/// Stops the server. In contrast to EVTCPServer::stop(), which also
		/// stops the server, but allows all client connections to finish at
		/// their pace, this allows finer control over client connections.
		///
		/// If abortCurrent is false, all current requests are allowed to
		/// complete. If abortCurrent is true, the underlying sockets of
		/// all client connections are shut down, causing all requests
		/// to abort.

	void setConfigNames(std::string serverPrefix, std::string numThreads, std::string receiveTimeOut,
				std::string numConnections, std::string useIpv6ForConn);
	void setServerPrefix(std::string serverPrefix);

private:
	EVHTTPRequestHandlerFactory::Ptr _pFactory;
	EVTCPServer *_pTCPServer;
};


} } // namespace Poco::evnet


#endif // Net__libev_EVHTTPServer_INCLUDED
