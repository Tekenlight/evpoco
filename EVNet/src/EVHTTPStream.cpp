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
#include "Poco/Net/HTTPSession.h"


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
	/*
	if (_mode & std::ios::out) {
        sync();
        _session.socket().shutdownSend();
    }
	*/
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
}


EVHTTPStreamBuf* EVHTTPIOS::rdbuf()
{
	return &_buf;
}


//
// EVHTTPInputStream
//


Poco::MemoryPool EVHTTPInputStream::_pool(sizeof(EVHTTPInputStream));


EVHTTPInputStream::EVHTTPInputStream(chunked_memory_stream *cms):
	EVHTTPIOS(cms, 1024),
	std::istream(&_buf)
{
}


EVHTTPInputStream::~EVHTTPInputStream()
{
}


void* EVHTTPInputStream::operator new(std::size_t size)
{
	return _pool.get();
}


void EVHTTPInputStream::operator delete(void* ptr)
{
	try
	{
		_pool.release(ptr);
	}
	catch (...)
	{
		poco_unexpected();
	}
}

/*

//
// HTTPOutputStream
//


Poco::MemoryPool HTTPOutputStream::_pool(sizeof(HTTPOutputStream));


HTTPOutputStream::HTTPOutputStream(HTTPSession& session):
	EVHTTPIOS(session, std::ios::out),
	std::ostream(&_buf)
{
}


HTTPOutputStream::~HTTPOutputStream()
{
}


void* HTTPOutputStream::operator new(std::size_t size)
{
	return _pool.get();
}


void HTTPOutputStream::operator delete(void* ptr)
{
	try
	{
		_pool.release(ptr);
	}
	catch (...)
	{
		poco_unexpected();
	}
}

*/

} } // namespace Poco::EVNet
