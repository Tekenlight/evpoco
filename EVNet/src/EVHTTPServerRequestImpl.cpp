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


#include "Poco/EVNet/EVHTTPServerRequestImpl.h"


using Poco::icompare;


namespace Poco {
namespace EVNet {


EVHTTPServerRequestImpl::EVHTTPServerRequestImpl(EVHTTPServerResponseImpl& response, HTTPServerSession& session, HTTPServerParams* pParams):
	_response(response),
	_session(session),
	_pStream(0),
	_pParams(pParams, true)
{
	response.attachRequest(this);

	HTTPHeaderInputStream hs(session);
	/* This call will land in read method of HTTPRequest.cpp
	 * request.
	 * */
	read(hs);
	
	// Now that we know socket is still connected, obtain addresses
	_clientAddress = session.clientAddress();
	_serverAddress = session.serverAddress();
	
	if (getChunkedTransferEncoding())
		_pStream = new HTTPChunkedInputStream(session);
	else if (hasContentLength())
#if defined(POCO_HAVE_INT64)
		_pStream = new HTTPFixedLengthInputStream(session, getContentLength64());
#else
		_pStream = new HTTPFixedLengthInputStream(session, getContentLength());
#endif
	else if (getMethod() == HTTPRequest::HTTP_GET || getMethod() == HTTPRequest::HTTP_HEAD || getMethod() == HTTPRequest::HTTP_DELETE)
		_pStream = new HTTPFixedLengthInputStream(session, 0);
	else
		_pStream = new HTTPInputStream(session);
}


EVHTTPServerRequestImpl::~EVHTTPServerRequestImpl()
{
	delete _pStream;
}


bool EVHTTPServerRequestImpl::secure() const
{
	return _session.socket().secure();
}


StreamSocket& EVHTTPServerRequestImpl::socket()
{
	return _session.socket();
}


StreamSocket EVHTTPServerRequestImpl::detachSocket()
{
	return _session.detachSocket();
}


} } // namespace Poco::EVNet
