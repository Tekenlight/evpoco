//
// EVHTTPServerRequestImpl.cpp
//
// Library: evnet
// Package: HTTPServer
// Module:  EVHTTPServerRequestImpl
//
// Tekenlight Solutions Pvt Ltd.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/evnet/evnet.h"
#include "Poco/evnet/EVHTTPServerRequestImpl.h"


using Poco::icompare;


namespace Poco {
namespace evnet {

/*
 * TBD:
 *
 * This needs to be totally repared.
 * Usage of session on the server side is quite unnecessary.
 * IO handling of request has to be event driven and neeed not be buffered.
 *
 * */
EVHTTPServerRequestImpl::EVHTTPServerRequestImpl(EVHTTPServerResponseImpl& response,
													EVServerSession& session,
													HTTPServerParams* pParams):
	_response(response),
	_pStream(0),
	_session(session),
	_pParams(pParams, true),
	_contentLength(0),
	_reqType(HTTP_INVALID_TYPE),
	_message_body_size(0),
	_continue_processed(false)
{
	response.attachRequest(this);
}

void EVHTTPServerRequestImpl::formInputStream(chunked_memory_stream * mem_inp_stream)
{
	if (getChunkedTransferEncoding()) {
		_pStream = new EVHTTPChunkedInputStream(mem_inp_stream, this->getMessageBodySize());
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



} } // namespace Poco::evnet
