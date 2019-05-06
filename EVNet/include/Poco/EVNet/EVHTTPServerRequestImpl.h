//
// EVHTTPServerRequestImpl.h
//
// Library: EVNet
// Package: HTTPServer
// Module:  EVHTTPServerRequestImpl
//
// Definition of the EVHTTPServerRequestImpl class.
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#ifndef EVNet_EVHTTPServerRequestImpl_INCLUDED
#define EVNet_EVHTTPServerRequestImpl_INCLUDED


#include "Poco/Net/Net.h"
#include "Poco/Net/HTTPServerRequest.h"
#include "Poco/EVNet/EVHTTPServerResponseImpl.h"
#include "Poco/Net/SocketAddress.h"
#include "Poco/Net/HTTPServerSession.h"
#include "Poco/Net/HTTPHeaderStream.h"
#include "Poco/Net/HTTPStream.h"
#include "Poco/Net/HTTPFixedLengthStream.h"
#include "Poco/Net/HTTPChunkedStream.h"
#include "Poco/Net/HTTPServerParams.h"
#include "Poco/Net/StreamSocket.h"
#include "Poco/AutoPtr.h"
#include "Poco/String.h"
#include <istream>

using Poco::Net::HTTPServerRequest;
//using Poco::Net::HTTPServerResponseImpl;
using Poco::Net::SocketAddress;
using Poco::Net::HTTPServerResponse;
using Poco::Net::HTTPChunkedInputStream;
using Poco::Net::HTTPFixedLengthInputStream;
using Poco::Net::HTTPServerSession;
using Poco::Net::HTTPServerParams;
using Poco::Net::StreamSocket;
using Poco::Net::HTTPHeaderInputStream;
using Poco::Net::HTTPInputStream;

namespace Poco {
	namespace Net {
		class HTTPServerSession;
		class HTTPServerParams;
		class StreamSocket;
	}

namespace EVNet {





class Net_API EVHTTPServerRequestImpl: public HTTPServerRequest
	/// This subclass of HTTPServerRequest is used for
	/// representing server-side HTTP requests.
	///
	/// A HTTPServerRequest is passed to the
	/// handleRequest() method of HTTPRequestHandler.
{
public:
	EVHTTPServerRequestImpl(EVHTTPServerResponseImpl& response, HTTPServerSession& session, HTTPServerParams* pParams);
		/// Creates the EVHTTPServerRequestImpl, using the
		/// given HTTPServerSession.

	//EVHTTPServerRequestImpl(EVHTTPServerResponseImpl &response, StreamSocket& socket, HTTPServerParams* pParams);
		/// Creates the EVHTTPServerRequestImpl, using the
		/// given StreamSocket.

	~EVHTTPServerRequestImpl();
		/// Destroys the EVHTTPServerRequestImpl.
		
	std::istream& stream();
		/// Returns the input stream for reading
		/// the request body.
		///
		/// The stream is valid until the EVHTTPServerRequestImpl
		/// object is destroyed.
		//
	
	const SocketAddress& clientAddress() const;
		/// Returns the client's address.

	const SocketAddress& serverAddress() const;
		/// Returns the server's address.
		
	const HTTPServerParams& serverParams() const;
		/// Returns a reference to the server parameters.

	HTTPServerResponse& response() const;
		/// Returns a reference to the associated response.
		
	bool secure() const;
		/// Returns true if the request is using a secure
		/// connection. Returns false if no secure connection
		/// is used, or if it is not known whether a secure
		/// connection is used.		
		
	StreamSocket& socket();
		/// Returns a reference to the underlying socket.
		
	StreamSocket detachSocket();
		/// Returns the underlying socket after detaching
		/// it from the server session.
		
	void formInputStream();
		/// Sets up the mechanism for reading of inputs from socket etc.
	
private:
	EVHTTPServerResponseImpl&       _response;
	HTTPServerSession&              _session;
	//StreamSocket&					_socket;
	std::istream*                   _pStream;
	Poco::AutoPtr<HTTPServerParams> _pParams;
	SocketAddress                   _clientAddress;
	SocketAddress                   _serverAddress;
};


//
// inlines
//
//
inline std::istream& EVHTTPServerRequestImpl::stream()
{
	poco_check_ptr (_pStream);
	
	return *_pStream;
}


inline const SocketAddress& EVHTTPServerRequestImpl::clientAddress() const
{
	return _clientAddress;
}


inline const SocketAddress& EVHTTPServerRequestImpl::serverAddress() const
{
	return _serverAddress;
}


inline const HTTPServerParams& EVHTTPServerRequestImpl::serverParams() const
{
	return *_pParams;
}


inline HTTPServerResponse& EVHTTPServerRequestImpl::response() const
{
	return _response;
}



} } // namespace Poco::EVNet


#endif // EVNet_EVHTTPServerRequestImpl_INCLUDED
