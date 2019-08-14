//
// EVHTTPServerRequestImpl.cpp
//
// Library: EVNet
// Package: HTTPServer
// Module:  EVHTTPServerRequestImpl
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/EVNet/EVNet.h"
#include "Poco/EVNet/EVHTTPServerRequestImpl.h"


using Poco::icompare;


namespace Poco {
namespace EVNet {

/*
 * TBD:
 *
 * This needs to be totally repared.
 * Usage of session on the server side is quite unnecessary.
 * IO handling of request has to be event driven and neeed not be buffered.
 *
 * */
EVHTTPServerRequestImpl::EVHTTPServerRequestImpl(EVHTTPServerResponseImpl& response,
													EVHTTPServerSession& session,
													HTTPServerParams* pParams):
	_response(response),
	_pStream(0),
	_session(session),
	_pParams(pParams, true),
	_contentLength(0),
	_reqType(HTTP_INVALID_TYPE)
{
	response.attachRequest(this);
	// Now that we know socket is still connected, obtain addresses
	_clientAddress = _session.clientAddress();;
	_serverAddress = _session.clientAddress();
}

void EVHTTPServerRequestImpl::formInputStream(chunked_memory_stream * mem_inp_stream)
{
	// Now that we know socket is still connected, obtain addresses
	_clientAddress = _session.clientAddress();
	_serverAddress = _session.serverAddress();

	if (getChunkedTransferEncoding()) {
		_pStream = new HTTPChunkedInputStream(_session);
	}
	else if (hasContentLength()) {
#if defined(POCO_HAVE_INT64)
		_pStream = new EVHTTPFixedLengthInputStream(mem_inp_stream, getContentLength64());
#else
		_pStream = new EVHTTPFixedLengthInputStream(mem_inp_stream, getContentLength());
#endif
	}
	else if (getMethod() == HTTPRequest::HTTP_GET ||
			getMethod() == HTTPRequest::HTTP_HEAD || getMethod() == HTTPRequest::HTTP_DELETE) {
		_pStream = new EVHTTPFixedLengthInputStream(mem_inp_stream, 0);
	}
	else {
		_pStream = new EVHTTPInputStream(mem_inp_stream);
	}
}

EVHTTPServerRequestImpl::~EVHTTPServerRequestImpl()
{
	delete _pStream;
}


bool EVHTTPServerRequestImpl::secure() const
{
	return _session.socket().secure();
}


StreamSocket EVHTTPServerRequestImpl::detachSocket()
{
	return _session.detachSocket();
}

StreamSocket& EVHTTPServerRequestImpl::socket()
{
	return _session.socket();
}



} } // namespace Poco::EVNet
