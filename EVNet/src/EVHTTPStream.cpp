//
// EVHTTPStream.cpp
//
// Library: EVNet
// Package: EVHTTP
// Module:  EVHTTPStream
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/EVNet/EVHTTPStream.h"
#include "Poco/StreamUtil.h"


namespace Poco {
namespace EVNet {


//
// EVHTTPStreamBuf
//


EVHTTPStreamBuf::EVHTTPStreamBuf(chunked_memory_stream *cms, openmode mode):
	ev_buffered_stream(cms, 1024),
	_mode(mode)
{
}


EVHTTPStreamBuf::~EVHTTPStreamBuf()
{
}

void EVHTTPStreamBuf::close()
{
	if (_mode & std::ios::out) {
		sync();
	}
	return ;
}

//
// EVHTTPIOS
//


EVHTTPIOS::EVHTTPIOS(chunked_memory_stream *cms, EVHTTPStreamBuf::openmode mode):
	_buf(cms, mode)
{
	poco_ios_init(&_buf);
}


EVHTTPIOS::~EVHTTPIOS()
{
	try
	{
		_buf.close();
	}
	catch (...)
	{
	}
}


EVHTTPStreamBuf* EVHTTPIOS::rdbuf()
{
	return &_buf;
}


//
// EVHTTPInputStream
//


EVHTTPInputStream::EVHTTPInputStream(chunked_memory_stream *cms):
	EVHTTPIOS(cms, 1024),
	std::istream(&_buf)
{
}


EVHTTPInputStream::~EVHTTPInputStream()
{
}




//
// EVHTTPOutputStream
//



EVHTTPOutputStream::EVHTTPOutputStream(chunked_memory_stream *cms):
	EVHTTPIOS(cms, std::ios::out),
	std::ostream(&_buf)
{
}


EVHTTPOutputStream::~EVHTTPOutputStream()
{
}


} } // namespace Poco::EVNet
