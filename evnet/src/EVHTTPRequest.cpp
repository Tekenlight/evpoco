//
// EVHTTPRequest.cpp
//
// Library: evnet
// Package: HTTP
// Module:  EVHTTPRequest
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/evnet/evnet.h"
#include "Poco/evnet/EVHTTPRequest.h"
#include "Poco/CountingStream.h"
#include "Poco/evnet/EVHTTPHeaderStream.h"
#include "Poco/evnet/EVHTTPChunkedStream.h"
#include "Poco/evnet/EVHTTPFixedLengthStream.h"

namespace Poco {
namespace evnet {

EVHTTPRequest::EVHTTPRequest():
	HTTPRequest("HTTP/1.1"),
	_msg_header(new chunked_memory_stream()),
	_msg_body(new chunked_memory_stream()),
	_msg_body_stream(0)
{
}

EVHTTPRequest::EVHTTPRequest(const std::string& method, const std::string& uri):
	HTTPRequest(method, uri, "HTTP/1.1"),
	_msg_header(new chunked_memory_stream()),
	_msg_body(new chunked_memory_stream()),
	_msg_body_stream(0)
{
}

EVHTTPRequest::~EVHTTPRequest()
{
	delete _msg_header;
	delete _msg_body;
	delete _msg_body_stream;
}

chunked_memory_stream* EVHTTPRequest::getMessageHeader()
{
	return _msg_header;
}

chunked_memory_stream* EVHTTPRequest::getMessageBody()
{
	if (_msg_body_stream) _msg_body_stream->flush();
	return _msg_body;
}

void EVHTTPRequest::prepareHeaderForSend()
{
	const std::string& method = getMethod();
	if (getChunkedTransferEncoding()) {
		EVHTTPHeaderOutputStream hos(_msg_header);
		write(hos);
		_msg_body_stream = new EVHTTPChunkedOutputStream(_msg_body);
	}
	else if (hasContentLength()) {
		EVHTTPHeaderOutputStream hos(_msg_header);
		write(hos);
#if POCO_HAVE_INT64
		_msg_body_stream = new EVHTTPFixedLengthOutputStream(_msg_body, getContentLength64());
#else
		_msg_body_stream = new EVHTTPFixedLengthOutputStream(_msg_body, getContentLength());
#endif
	}
	else if ((method != HTTPRequest::HTTP_PUT && method != HTTPRequest::HTTP_POST && method != HTTPRequest::HTTP_PATCH) || has(HTTPRequest::UPGRADE)) {
		EVHTTPHeaderOutputStream hos(_msg_header);
		write(hos);
	}
	else {
		/*
		_msg_body_stream = new HTTPOutputStream(*this);
		request.write(*_msg_body_stream);
		*/
		DEBUGPOINT("A request message originating should be one of header-only , or fixed length, or chunked\n");
		std::abort();
	}

	return ;
}

std::ostream* EVHTTPRequest::getRequestStream()
{
	return _msg_body_stream;
}

}
}
