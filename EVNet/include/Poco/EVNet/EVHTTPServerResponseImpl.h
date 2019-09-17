//
// EVHTTPServerResponseImpl.h
//
// Library: EVNet
// Package: EVHTTPServer
// Module:  EVHTTPServerResponseImpl
//
// Definition of the EVHTTPServerResponseImpl class.
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#ifndef EVNet_EVHTTPServerResponseImpl_INCLUDED
#define EVNet_EVHTTPServerResponseImpl_INCLUDED


#include "Poco/Net/Net.h"
#include "Poco/Net/HTTPServerResponse.h"
#include "Poco/Net/HTTPRequest.h"

#include "Poco/Net/HTTPServerSession.h"
#include "Poco/EVNet/EVHTTPServerSession.h"
#include "Poco/Net/HTTPHeaderStream.h"
#include "Poco/Net/HTTPStream.h"
#include "Poco/Net/HTTPFixedLengthStream.h"
#include "Poco/Net/HTTPChunkedStream.h"

#include "Poco/EVNet/EVHTTPHeaderStream.h"
#include "Poco/EVNet/EVHTTPStream.h"
#include "Poco/EVNet/EVHTTPFixedLengthStream.h"
#include "Poco/EVNet/EVHTTPChunkedStream.h"

#include "Poco/File.h"
#include "Poco/Timestamp.h"
#include "Poco/NumberFormatter.h"
#include "Poco/StreamCopier.h"
#include "Poco/CountingStream.h"
#include "Poco/Exception.h"
#include "Poco/FileStream.h"
#include "Poco/DateTimeFormatter.h"
#include "Poco/DateTimeFormat.h"

#include <chunked_memory_stream.h>

using Poco::Net::HTTPServerResponse;
using Poco::Net::HTTPServerSession;
using Poco::Net::HTTPHeaderOutputStream;
using Poco::Net::HTTPRequest;
using Poco::Net::HTTPFixedLengthOutputStream;
using Poco::Net::HTTPHeaderOutputStream;
using Poco::Net::HTTPChunkedOutputStream;
using Poco::Net::HTTPFixedLengthOutputStream;
using Poco::Net::HTTPOutputStream;
using Poco::Net::HTTPHeaderOutputStream;

namespace Poco {
	namespace Net {
		class HTTPServerSession;
	}
namespace EVNet {


class EVHTTPServerRequestImpl;


class Net_API EVHTTPServerResponseImpl: public HTTPServerResponse
	/// This subclass of HTTPServerResponse is used for
	/// representing server-side HTTP responses.
	///
	/// A HTTPServerResponse is passed to the
	/// handleRequest() method of HTTPRequestHandler.
	///
	/// handleRequest() must set a status code
	/// and optional reason phrase, set headers
	/// as necessary, and provide a message body.
{
public:
	EVHTTPServerResponseImpl(EVHTTPServerRequestImpl *request,EVHTTPServerSession& session);
		/// Creates the EVHTTPServerResponseImpl.

	EVHTTPServerResponseImpl(EVHTTPServerSession& session);
		/// Creates the EVHTTPServerResponseImpl.

	~EVHTTPServerResponseImpl();
		/// Destroys the EVHTTPServerResponseImpl.
	void attachSession(EVHTTPServerSession &session);

	void sendContinue();
		/// Sends a 100 Continue response to the
		/// client.
		
	std::ostream& send();
		/// Sends the response header to the client and
		/// returns an output stream for sending the
		/// response body.
		///
		/// The returned stream is valid until the response
		/// object is destroyed.
		///
		/// Must not be called after sendFile(), sendBuffer() 
		/// or redirect() has been called.
		
	void sendFile(const std::string& path, const std::string& mediaType);
		/// Sends the response header to the client, followed
		/// by the content of the given file.
		///
		/// Must not be called after send(), sendBuffer() 
		/// or redirect() has been called.
		///
		/// Throws a FileNotFoundException if the file
		/// cannot be found, or an OpenFileException if
		/// the file cannot be opened.
		
	void sendBuffer(const void* pBuffer, std::size_t length);
		/// Sends the response header to the client, followed
		/// by the contents of the given buffer.
		///
		/// The Content-Length header of the response is set
		/// to length and chunked transfer encoding is disabled.
		///
		/// If both the HTTP message header and body (from the
		/// given buffer) fit into one single network packet, the 
		/// complete response can be sent in one network packet.
		///
		/// Must not be called after send(), sendFile()  
		/// or redirect() has been called.
		
	void redirect(const std::string& uri, HTTPStatus status = HTTP_FOUND);
		/// Sets the status code, which must be one of
		/// HTTP_MOVED_PERMANENTLY (301), HTTP_FOUND (302),
		/// or HTTP_SEE_OTHER (303),
		/// and sets the "Location" header field
		/// to the given URI, which according to
		/// the HTTP specification, must be absolute.
		///
		/// Must not be called after send() has been called.
		
	void requireAuthentication(const std::string& realm);
		/// Sets the status code to 401 (Unauthorized)
		/// and sets the "WWW-Authenticate" header field
		/// according to the given realm.
		
	bool sent() const;
		/// Returns true if the response (header) has been sent.

	void attachRequest(EVHTTPServerRequestImpl* pRequest);

	void setMemoryStream(chunked_memory_stream* cms);

	virtual std::ostream & getOStream();
protected:
	
private:
	EVHTTPServerSession& _session;
	EVHTTPServerRequestImpl* _pRequest;
	std::ostream*      _pStream;
	chunked_memory_stream* _out_memory_stream;
	
	friend class EVHTTPServerRequestImpl;
};


//
// inlines
inline void EVHTTPServerResponseImpl::attachSession(EVHTTPServerSession & session)
{
	_session = session;
}

//
inline bool EVHTTPServerResponseImpl::sent() const
{
	return _pStream != 0;
}


inline void EVHTTPServerResponseImpl::attachRequest(EVHTTPServerRequestImpl* pRequest)
{
	_pRequest = pRequest;
}


} } // namespace Poco::EVNet


#endif // EVNet_EVHTTPServerResponseImpl_INCLUDED
