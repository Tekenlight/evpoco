//
// EVHTTPHeaderStream.cpp
//
// Library: EVNet
// Package: HTTP
// Module:  EVHTTPHeaderStream
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/EVNet/EVNet.h"
#include "Poco/EVNet/EVHTTPHeaderStream.h"
#include "Poco/StreamUtil.h"


namespace Poco {
namespace EVNet {


//
// EVHTTPHeaderStreamBuf
//


EVHTTPHeaderStreamBuf::EVHTTPHeaderStreamBuf(chunked_memory_stream *cms, openmode mode):
	ev_buffered_stream(cms, 1024)
{
}


EVHTTPHeaderStreamBuf::~EVHTTPHeaderStreamBuf()
{
}

void EVHTTPHeaderStreamBuf::pre_write_buffer(char* buffer, std::streamsize bytes, char **buffer_ptr, size_t *bytes_ptr)
{
	printf("%s",buffer);
}

/*
int EVHTTPHeaderStreamBuf::readFromDevice(char* buffer, std::streamsize length)
{
	// read line-by-line; an empty line denotes the end of the headers.
	static const int eof = std::char_traits<char>::eof();

	if (_end) return 0;

	int n = 0;
	int ch = _session.get();
	while (ch != eof && ch != '\n' && n < length - 1)
	{
		*buffer++ = (char) ch; ++n;
		ch = _session.get();
	}
	if (ch != eof)
	{
		*buffer++ = (char) ch; ++n;
		if (n == 2) _end = true;
	}
	return n;
}


int EVHTTPHeaderStreamBuf::writeToDevice(const char* buffer, std::streamsize length)
{
	return _session.write(buffer, length);
}
*/


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



} } // namespace Poco::EVNet
