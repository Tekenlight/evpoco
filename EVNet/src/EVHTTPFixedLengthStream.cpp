//
// HTTPFixedLengthStream.cpp
//
// Library: EVNet
// Package: HTTP
// Module:  EVHTTPFixedLengthStream
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/StreamUtil.h"
#include "Poco/EVNet/EVHTTPFixedLengthStream.h"


namespace Poco {
namespace EVNet {


//
// EVHTTPFixedLengthStreamBuf
//


EVHTTPFixedLengthStreamBuf::EVHTTPFixedLengthStreamBuf(chunked_memory_stream *cms, ContentLength length, openmode mode):
	ev_buffered_stream(cms, 1024, length)
{
}


EVHTTPFixedLengthStreamBuf::~EVHTTPFixedLengthStreamBuf()
{
}



//
// EVHTTPFixedLengthIOS
//


EVHTTPFixedLengthIOS::EVHTTPFixedLengthIOS(chunked_memory_stream *cms, EVHTTPFixedLengthStreamBuf::ContentLength length, EVHTTPFixedLengthStreamBuf::openmode mode):
	_buf(cms, length, mode)
{
	poco_ios_init(&_buf);
}


EVHTTPFixedLengthIOS::~EVHTTPFixedLengthIOS()
{
	try
	{
		//_buf.sync(); TBD
	}
	catch (...)
	{
	}
}


EVHTTPFixedLengthStreamBuf* EVHTTPFixedLengthIOS::rdbuf()
{
	return &_buf;
}


//
// EVHTTPFixedLengthInputStream
//


Poco::MemoryPool EVHTTPFixedLengthInputStream::_pool(sizeof(EVHTTPFixedLengthInputStream));


EVHTTPFixedLengthInputStream::EVHTTPFixedLengthInputStream(chunked_memory_stream *cms, EVHTTPFixedLengthStreamBuf::ContentLength length):
	EVHTTPFixedLengthIOS(cms, length, std::ios::in),
	std::istream(&_buf)
{
}


EVHTTPFixedLengthInputStream::~EVHTTPFixedLengthInputStream()
{
}


void* EVHTTPFixedLengthInputStream::operator new(std::size_t size)
{
	return _pool.get();
}

void EVHTTPFixedLengthInputStream::operator delete(void* ptr)
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


//
// HTTPFixedLengthOutputStream
//

/*

Poco::MemoryPool HTTPFixedLengthOutputStream::_pool(sizeof(HTTPFixedLengthOutputStream));


HTTPFixedLengthOutputStream::HTTPFixedLengthOutputStream(HTTPSession& session, EVHTTPFixedLengthStreamBuf::ContentLength length):
	EVHTTPFixedLengthIOS(session, length, std::ios::out),
	std::ostream(&_buf)
{
}


HTTPFixedLengthOutputStream::~HTTPFixedLengthOutputStream()
{
}


void* HTTPFixedLengthOutputStream::operator new(std::size_t size)
{
	return _pool.get();
}


void HTTPFixedLengthOutputStream::operator delete(void* ptr)
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
