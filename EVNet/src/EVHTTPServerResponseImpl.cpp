//
// EVHTTPServerResponseImpl.cpp
//
// Library: EVNet
// Package: EVHTTPServer
// Module:  EVHTTPServerResponseImpl
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/EVNet/EVHTTPServerResponseImpl.h"
#include "Poco/EVNet/EVHTTPServerRequestImpl.h"
#include "Poco/EVNet/EVNet.h"

using Poco::File;
using Poco::Timestamp;
using Poco::NumberFormatter;
using Poco::StreamCopier;
using Poco::OpenFileException;
using Poco::DateTimeFormatter;
using Poco::DateTimeFormat;


namespace Poco {
namespace EVNet {


EVHTTPServerResponseImpl::EVHTTPServerResponseImpl(EVHTTPServerRequestImpl * request,HTTPServerSession& session):
	_session(session),
	_pRequest(request),
	_pStream(0)
{
}

EVHTTPServerResponseImpl::EVHTTPServerResponseImpl(HTTPServerSession& session):
	_session(session),
	_pRequest(0),
	_pStream(0)
{
}


EVHTTPServerResponseImpl::~EVHTTPServerResponseImpl()
{
	delete _pStream;
}


void EVHTTPServerResponseImpl::sendContinue()
{
	HTTPHeaderOutputStream hs(_session);
	hs << getVersion() << " 100 Continue\r\n\r\n";
}

std::ostream& EVHTTPServerResponseImpl::send()
{
	poco_assert (!_pStream);

	if ((_pRequest && _pRequest->getMethod() == HTTPRequest::HTTP_HEAD) ||
		getStatus() < 200 ||
		getStatus() == HTTPResponse::HTTP_NO_CONTENT ||
		getStatus() == HTTPResponse::HTTP_NOT_MODIFIED)
	{
		Poco::CountingOutputStream cs;
		write(cs);
		_pStream = new HTTPFixedLengthOutputStream(_session, cs.chars());
		write(*_pStream);
	}
	else if (getChunkedTransferEncoding())
	{
		HTTPHeaderOutputStream hs(_session);
		write(hs);
		_pStream = new HTTPChunkedOutputStream(_session);
	}
	else if (hasContentLength())
	{
		Poco::CountingOutputStream cs;
		write(cs);
#if defined(POCO_HAVE_INT64)	
		_pStream = new HTTPFixedLengthOutputStream(_session, getContentLength64() + cs.chars());
#else
		_pStream = new HTTPFixedLengthOutputStream(_session, getContentLength() + cs.chars());
#endif
		write(*_pStream);
	}
	else
	{
		_pStream = new HTTPOutputStream(_session);
		setKeepAlive(false);
		write(*_pStream);
	}
	return *_pStream;
}


void EVHTTPServerResponseImpl::sendFile(const std::string& path, const std::string& mediaType)
{
	poco_assert (!_pStream);

	File f(path);
	Timestamp dateTime    = f.getLastModified();
	File::FileSize length = f.getSize();
	set("Last-Modified", DateTimeFormatter::format(dateTime, DateTimeFormat::HTTP_FORMAT));
#if defined(POCO_HAVE_INT64)	
	setContentLength64(length);
#else
	setContentLength(static_cast<int>(length));
#endif
	setContentType(mediaType);
	setChunkedTransferEncoding(false);

	Poco::FileInputStream istr(path);
	if (istr.good())
	{
		_pStream = new HTTPHeaderOutputStream(_session);
		write(*_pStream);
		if (_pRequest && _pRequest->getMethod() != HTTPRequest::HTTP_HEAD)
		{
			StreamCopier::copyStream(istr, *_pStream);
		}
	}
	else throw OpenFileException(path);
}


void EVHTTPServerResponseImpl::sendBuffer(const void* pBuffer, std::size_t length)
{
	poco_assert (!_pStream);

	setContentLength(static_cast<int>(length));
	setChunkedTransferEncoding(false);
	
	_pStream = new HTTPHeaderOutputStream(_session);
	write(*_pStream);
	if (_pRequest && _pRequest->getMethod() != HTTPRequest::HTTP_HEAD)
	{
		_pStream->write(static_cast<const char*>(pBuffer), static_cast<std::streamsize>(length));
	}
}


void EVHTTPServerResponseImpl::redirect(const std::string& uri, HTTPStatus status)
{
	poco_assert (!_pStream);

	setContentLength(0);
	setChunkedTransferEncoding(false);

	setStatusAndReason(status);
	set("Location", uri);

	_pStream = new HTTPHeaderOutputStream(_session);
	write(*_pStream);
}


void EVHTTPServerResponseImpl::requireAuthentication(const std::string& realm)
{
	poco_assert (!_pStream);
	
	setStatusAndReason(HTTPResponse::HTTP_UNAUTHORIZED);
	std::string auth("Basic realm=\"");
	auth.append(realm);
	auth.append("\"");
	set("WWW-Authenticate", auth);
}


} } // namespace Poco::EVNet
