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


EVHTTPServerResponseImpl::EVHTTPServerResponseImpl(EVHTTPServerRequestImpl * request,EVHTTPServerSession& session):
	_session(session),
	_pRequest(request),
	_pStream(0),
	_out_memory_stream(0)
{
}

EVHTTPServerResponseImpl::EVHTTPServerResponseImpl(EVHTTPServerSession& session):
	_session(session),
	_pRequest(0),
	_pStream(0),
	_out_memory_stream(0)
{
}


EVHTTPServerResponseImpl::~EVHTTPServerResponseImpl()
{
	delete _pStream;
}


void EVHTTPServerResponseImpl::sendContinue()
{
	EVHTTPHeaderOutputStream hs(_session, _out_memory_stream);
	hs << getVersion() << " 100 Continue\r\n\r\n";
}

void EVHTTPServerResponseImpl::setMemoryStream(chunked_memory_stream* cms)
{
	if (!_out_memory_stream) _out_memory_stream = cms;
}

std::ostream& EVHTTPServerResponseImpl::send()
{
	poco_assert (!_pStream);

	//DEBUGPOINT(" oms = %p\n", _out_memory_stream);
	poco_assert (_out_memory_stream);

	if ((_pRequest && _pRequest->getMethod() == HTTPRequest::HTTP_HEAD) ||
		getStatus() < 200 ||
		getStatus() == HTTPResponse::HTTP_NO_CONTENT ||
		getStatus() == HTTPResponse::HTTP_NOT_MODIFIED)
	{
		Poco::CountingOutputStream cs;
		write(cs);
		_pStream = new EVHTTPFixedLengthOutputStream(_out_memory_stream, cs.chars());
		write(*_pStream);
	}
	else if (getChunkedTransferEncoding())
	{
		EVHTTPHeaderOutputStream hs(_session, _out_memory_stream);
		write(hs);
		_pStream = new EVHTTPChunkedOutputStream(_out_memory_stream);
	}
	else if (hasContentLength())
	{
		Poco::CountingOutputStream cs;
		write(cs);
#if defined(POCO_HAVE_INT64)	
		_pStream = new EVHTTPFixedLengthOutputStream(_out_memory_stream, getContentLength64() + cs.chars());
#else
		_pStream = new EVHTTPFixedLengthOutputStream(_out_memory_stream, getContentLength() + cs.chars());
#endif
		write(*_pStream);
	}
	else
	{
		_pStream = new EVHTTPOutputStream(_out_memory_stream);
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
		_pStream = new EVHTTPHeaderOutputStream(_session, _out_memory_stream);
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
	
	_pStream = new EVHTTPHeaderOutputStream(_session, _out_memory_stream);
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

	_pStream = new EVHTTPHeaderOutputStream(_session, _out_memory_stream);
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
