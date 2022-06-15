//
// EVCLServerRequestImpl.h
//
// Library: evnet
// Package: HTTPServer
// Module:  EVCLServerRequestImpl
//
// Definition of the EVCLServerRequestImpl class.
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#ifndef EVNet_EVCLServerRequestImpl_INCLUDED
#define EVNet_EVCLServerRequestImpl_INCLUDED


#include "Poco/Net/Net.h"
#include "Poco/Net/HTTPServerRequest.h"
#include "Poco/evnet/EVCLServerResponseImpl.h"
#include "Poco/Net/SocketAddress.h"
#include "Poco/Net/HTTPServerSession.h"
#include "Poco/evnet/EVServerRequest.h"
#include "Poco/evnet/EVServerSession.h"
#include "Poco/Net/HTTPHeaderStream.h"
#include "Poco/Net/HTTPStream.h"
#include "Poco/evnet/EVHTTPStream.h"
#include "Poco/Net/HTTPFixedLengthStream.h"
#include "Poco/evnet/EVHTTPFixedLengthStream.h"
#include "Poco/evnet/EVHTTPChunkedStream.h"
#include "Poco/Net/HTTPServerParams.h"
#include "Poco/Net/StreamSocket.h"
#include "Poco/AutoPtr.h"
#include "Poco/String.h"
#include <istream>
#include <chunked_memory_stream.h>

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

namespace evnet {

class Net_API EVCLServerRequestImpl: public EVServerRequest
	/// This subclass of HTTPServerRequest is used for
	/// representing server-side HTTP requests.
	///
	/// A HTTPServerRequest is passed to the
	/// handleRequest() method of HTTPRequestHandler.
{
public:
	EVCLServerRequestImpl(EVCLServerResponseImpl& response, EVServerSession& session);
		/// Creates the EVCLServerRequestImpl, using the
		/// given EVServerSession.

	~EVCLServerRequestImpl();
		/// Destroys the EVCLServerRequestImpl.
		
	EVCLServerResponseImpl& response() const;
		/// Returns a reference to the associated response.
		
	void setMessageBodySize(size_t len);
	size_t getMessageBodySize();

	void setBuf(char *);
	char *getBuf();

	virtual int getReqMode();

private:
	EVCLServerResponseImpl&       	_response;
	EVServerSession&            	_session;
	size_t							_message_body_size;
	char *							_buf;
};


//
// inlines
//
//

inline int EVCLServerRequestImpl::getReqMode()
{
	return EVServerRequest::CL_REQ;
}


inline void EVCLServerRequestImpl::setBuf(char * buf)
{
	_buf = buf;
}

inline char * EVCLServerRequestImpl::getBuf()
{
	return _buf;
}

inline EVCLServerResponseImpl& EVCLServerRequestImpl::response() const
{
	return _response;
}

inline void EVCLServerRequestImpl::setMessageBodySize(size_t len)
{
	_message_body_size = len;
}

inline size_t EVCLServerRequestImpl::getMessageBodySize()
{
	return _message_body_size;
}

} } // namespace Poco::evnet


#endif // EVNet_EVCLServerRequestImpl_INCLUDED
