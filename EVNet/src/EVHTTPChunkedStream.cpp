//
// EVHTTPChunkedStream.cpp
//
// Library: EVNet
// Package: HTTP
// Module:  EVHTTPChunkedStream
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include <stdlib.h>
#include "Poco/EVNet/EVNet.h"
#include "Poco/EVNet/EVHTTPChunkedStream.h"
#include "Poco/NumberFormatter.h"
#include "Poco/NumberParser.h"
#include "Poco/Ascii.h"
#include "Poco/StreamUtil.h"


using Poco::NumberFormatter;
using Poco::NumberParser;



namespace Poco {
namespace EVNet {

EVHTTPChunkedStreamBuf::EVHTTPChunkedStreamBuf(chunked_memory_stream *cms, openmode mode):
	ev_buffered_stream(cms, 1024),
	_mode(mode),
	_chunk(0)
{
}

EVHTTPChunkedStreamBuf::~EVHTTPChunkedStreamBuf()
{
}

void EVHTTPChunkedStreamBuf::close()
{
	/* THIS IS JUNK */
	if (_mode & std::ios::out) {
		std::ostream os(this);
		os << "0\r\n\r\n";
		sync();
		//_session.write("0\r\n\r\n", 5);
	}
}


int EVHTTPChunkedStreamBuf::readFromDevice(char* buffer, std::streamsize length)
{
	/*
	static const int eof = std::char_traits<char>::eof();

	if (_chunk == 0)
	{
		int ch = _session.get();
		while (Poco::Ascii::isSpace(ch)) ch = _session.get();
		std::string chunkLen;
		while (Poco::Ascii::isHexDigit(ch) && chunkLen.size() < 8) { chunkLen += (char) ch; ch = _session.get(); }
		if (ch != eof && !(Poco::Ascii::isSpace(ch) || ch == ';')) return eof;
		while (ch != eof && ch != '\n') ch = _session.get();
		unsigned chunk;
		if (NumberParser::tryParseHex(chunkLen, chunk))
			_chunk = (std::streamsize) chunk;
		else
			return eof;
	}
	if (_chunk > 0)
	{
		if (length > _chunk) length = _chunk;
		int n = _session.read(buffer, length);
		if (n > 0) _chunk -= n;
		return n;
	}
	else 
	{
		int ch = _session.get();
		while (ch != eof && ch != '\n') ch = _session.get();
		return 0;
	}
	*/
	return 0;
}

void EVHTTPChunkedStreamBuf::pre_write_buffer(char* buffer, std::streamsize bytes, char **buffer_ptr, size_t *bytes_ptr)
{
	*buffer_ptr = (char*)malloc(128);
	memset(*buffer_ptr, 0, 128);

	{
		std::string buf;
		buf.clear();
		NumberFormatter::appendHex(buf, bytes);
		buf.append("\r\n", 2);
		memcpy(*buffer_ptr, buf.c_str(), static_cast<std::streamsize>(buf.size()));
		*bytes_ptr = static_cast<std::streamsize>(buf.size());
		printf("%s",*buffer_ptr);
		printf("%s",buffer);
	}
}

void EVHTTPChunkedStreamBuf::post_write_buffer(char* buffer, std::streamsize bytes, char **buffer_ptr, size_t *bytes_ptr)
{
	*buffer_ptr = (char*)malloc(128);
	memset(*buffer_ptr, 0, 128);

	{
		static int count = 0;
		count++;
		std::string buf;
		buf.clear();
		buf.append("\r\n", 2);
		memcpy(*buffer_ptr, buf.c_str(), static_cast<std::streamsize>(buf.size()));
		*bytes_ptr = static_cast<std::streamsize>(buf.size());
		printf("%s",*buffer_ptr);
		printf("--------------------------------------------count = %d---------------------------------------------\n",count);
	}
}

/*
int EVHTTPChunkedStreamBuf::writeToDevice(const char* buffer, std::streamsize length)
{
	_chunkBuffer.clear();
	NumberFormatter::appendHex(_chunkBuffer, length);
	_chunkBuffer.append("\r\n", 2);
	_chunkBuffer.append(buffer, static_cast<std::string::size_type>(length));
	_chunkBuffer.append("\r\n", 2);
	_session.write(_chunkBuffer.data(), static_cast<std::streamsize>(_chunkBuffer.size()));
	return static_cast<int>(length);
	return 0;
}
*/

EVHTTPChunkedIOS::EVHTTPChunkedIOS(chunked_memory_stream *cms, EVHTTPChunkedStreamBuf::openmode mode):
	_buf(cms, mode)
{
	poco_ios_init(&_buf);
}

EVHTTPChunkedIOS::~EVHTTPChunkedIOS()
{
	try
	{
		_buf.close();
	}
	catch (...)
	{
	}
}

EVHTTPChunkedStreamBuf* EVHTTPChunkedIOS::rdbuf()
{
	return &_buf;
}

/*
Poco::MemoryPool EVHTTPChunkedInputStream::_pool(sizeof(EVHTTPChunkedInputStream));
Poco::MemoryPool EVHTTPChunkedOutputStream::_pool(sizeof(EVHTTPChunkedOutputStream));
*/

EVHTTPChunkedInputStream::EVHTTPChunkedInputStream(chunked_memory_stream *cms):
	EVHTTPChunkedIOS(cms, std::ios::in),
	std::istream(&_buf)
{
}

EVHTTPChunkedInputStream::~EVHTTPChunkedInputStream()
{
}

/*
void* EVHTTPChunkedInputStream::operator new(std::size_t size)
{
	return _pool.get();
}

void EVHTTPChunkedInputStream::operator delete(void* ptr)
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

	
EVHTTPChunkedOutputStream::EVHTTPChunkedOutputStream(chunked_memory_stream *cms):
	EVHTTPChunkedIOS(cms, std::ios::out),
	std::ostream(&_buf)
{
}

EVHTTPChunkedOutputStream::~EVHTTPChunkedOutputStream()
{
}

/*
void* EVHTTPChunkedOutputStream::operator new(std::size_t size)
{
	return _pool.get();
}

void EVHTTPChunkedOutputStream::operator delete(void* ptr)
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

	
} } // namespace Poco::Net

