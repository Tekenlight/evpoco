//
// EVHTTPHeaderStream.cpp
//
// Library: evnet
// Package: HTTP
// Module:  EVHTTPHeaderStream
//
// Tekenlight Solutions Pvt Ltd.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/evnet/evnet.h"
#include "Poco/evnet/EVHTTPHeaderStream.h"
#include "Poco/StreamUtil.h"


namespace Poco {
namespace evnet {


//
// EVHTTPHeaderStreamBuf
//


EVHTTPHeaderStreamBuf::EVHTTPHeaderStreamBuf(chunked_memory_stream *cms, openmode mode):
	ev_buffered_stream(cms, 1024)
{
	set_mode(mode);
}


EVHTTPHeaderStreamBuf::~EVHTTPHeaderStreamBuf()
{
	//_session.getServer()->dataReadyForSend(_session.socket().impl()->sockfd());
}

void EVHTTPHeaderStreamBuf::get_prefix(char* buffer, std::streamsize bytes, char *prefix, size_t prefix_len)
{
}

//
// EVHTTPHeaderIOS
//


EVHTTPHeaderIOS::EVHTTPHeaderIOS(chunked_memory_stream *cms, EVHTTPHeaderStreamBuf::openmode mode):
	_buf(cms, mode)
{
	poco_ios_init(&_buf);
}


EVHTTPHeaderIOS::~EVHTTPHeaderIOS()
{
	try
	{
		_buf.sync();
	}
	catch (std::exception& e)
	{
		DEBUGPOINT("Here %s\n",e.what());
		throw e;
	}
	catch (...) {
		throw;
	}
}


EVHTTPHeaderStreamBuf* EVHTTPHeaderIOS::rdbuf()
{
	return &_buf;
}


//
// EVHTTPHeaderInputStream
//


EVHTTPHeaderInputStream::EVHTTPHeaderInputStream(chunked_memory_stream *cms):
	EVHTTPHeaderIOS(cms, std::ios::in),
	std::istream(&_buf)
{
}


EVHTTPHeaderInputStream::~EVHTTPHeaderInputStream()
{
}

//
// EVHTTPHeaderOutputStream
//


EVHTTPHeaderOutputStream::EVHTTPHeaderOutputStream(chunked_memory_stream *cms):
	EVHTTPHeaderIOS(cms, std::ios::out),
	std::ostream(&_buf)
{
}


EVHTTPHeaderOutputStream::~EVHTTPHeaderOutputStream()
{
}



} } // namespace Poco::evnet
