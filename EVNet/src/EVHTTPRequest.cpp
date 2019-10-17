//
// EVHTTPRequest.cpp
//
// Library: EVNet
// Package: HTTP
// Module:  EVHTTPRequest
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/EVNet/EVNet.h"
#include "Poco/EVNet/EVHTTPRequest.h"
#include "Poco/EVNet/EVHTTPHeaderStream.h"


namespace Poco {
namespace EVNet {

EVHTTPRequest::EVHTTPRequest():
HTTPRequest("HTTP/1.1"),
_msg_body(new chunked_memory_stream())
{
}

EVHTTPRequest::EVHTTPRequest(const std::string& method, const std::string& uri):
HTTPRequest(method, uri, "HTTP/1.1"),
_msg_body(new chunked_memory_stream())
{
}

EVHTTPRequest::~EVHTTPRequest()
{
}

std::ostream& EVHTTPRequest::prepareRequestStream()
{
	/*
	const std::string& method = getMethod();
	if (getChunkedTransferEncoding()) {
		EVHTTPHeaderOutputStream hos(*this);
		request.write(hos);
		_pRequestStream = new HTTPChunkedOutputStream(*this);
	}
	else if (request.hasContentLength())
	{
		Poco::CountingOutputStream cs;
		request.write(cs);
#if POCO_HAVE_INT64
		_pRequestStream = new HTTPFixedLengthOutputStream(*this, request.getContentLength64() + cs.chars());
#else
		_pRequestStream = new HTTPFixedLengthOutputStream(*this, request.getContentLength() + cs.chars());
#endif
		request.write(*_pRequestStream);
	}
	else if ((method != HTTPRequest::HTTP_PUT && method != HTTPRequest::HTTP_POST && method != HTTPRequest::HTTP_PATCH) || request.has(HTTPRequest::UPGRADE))
	{
		Poco::CountingOutputStream cs;
		request.write(cs);
		_pRequestStream = new HTTPFixedLengthOutputStream(*this, cs.chars());
		request.write(*_pRequestStream);
	}
	else
	{
		_pRequestStream = new HTTPOutputStream(*this);
		request.write(*_pRequestStream);
	}	
	*/
	return *_message_body_stream;
}

std::ostream& EVHTTPRequest::getRequestStream()
{
	return *_message_body_stream;
}

}
}
