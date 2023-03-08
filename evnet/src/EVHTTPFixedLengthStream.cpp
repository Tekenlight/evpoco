//
// HTTPFixedLengthStream.cpp
//
// Library: evnet
// Package: HTTP
// Module:  EVHTTPFixedLengthStream
//
// Tekenlight Solutions Pvt Ltd.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/StreamUtil.h"
#include "Poco/evnet/EVHTTPFixedLengthStream.h"


namespace Poco {
namespace evnet {


//
// EVHTTPFixedLengthStreamBuf
//


EVHTTPFixedLengthStreamBuf::EVHTTPFixedLengthStreamBuf(chunked_memory_stream *cms, ContentLength length, openmode mode):
	ev_buffered_stream(cms, 1024, length)
{
	set_mode(mode);
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
	//DEBUGPOINT("Cumulative body length = %zu\n", length);
	_buf.consume_all_of_max_len();
}


EVHTTPFixedLengthIOS::~EVHTTPFixedLengthIOS()
{
	try
	{
		_buf.sync();
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


EVHTTPFixedLengthInputStream::EVHTTPFixedLengthInputStream(chunked_memory_stream *cms, EVHTTPFixedLengthStreamBuf::ContentLength length):
	EVHTTPFixedLengthIOS(cms, length, std::ios::in),
	std::istream(&_buf)
{
}


EVHTTPFixedLengthInputStream::~EVHTTPFixedLengthInputStream()
{
}


//
// EVHTTPFixedLengthOutputStream
//


EVHTTPFixedLengthOutputStream::EVHTTPFixedLengthOutputStream(chunked_memory_stream *cms, EVHTTPFixedLengthStreamBuf::ContentLength length):
	EVHTTPFixedLengthIOS(cms, length, std::ios::out),
	std::ostream(&_buf)
{
}


EVHTTPFixedLengthOutputStream::~EVHTTPFixedLengthOutputStream()
{
}


} } // namespace Poco::evnet
