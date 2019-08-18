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
	_chunk(0),
	_closed_state(0)
{
	set_prefix_len(5);
	set_suffix_len(2);
}

EVHTTPChunkedStreamBuf::~EVHTTPChunkedStreamBuf()
{
}

void EVHTTPChunkedStreamBuf::close()
{
	if (_mode & std::ios::out) {
		sync();
		_closed_state = 1;
		std::ostream os(this);
		os << "\r\n";
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

void EVHTTPChunkedStreamBuf::get_prefix(char* buffer, std::streamsize bytes, char *prefix, size_t prefix_len)
{
	//if (_closed_state) return;
	int buf0_len = 0;


	{
		std::string buf0;
		std::string buf;
		buf.clear();
		buf0.clear();
		if (_closed_state) {
			NumberFormatter::appendHex(buf0, 0);
			if (strncmp("\r\n", buffer, 2)) std::abort();
			if (('\r' != buffer[0]) || ('\n' != buffer[1])) std::abort();
		}
		else {
			NumberFormatter::appendHex(buf0, bytes);
			buf0.append("\r\n", 2);
		}
		{
			int i = 0;
			while (prefix_len>(buf0.size()+buf.size())) {
				buf.append("0",1);
				i++;
				if (i>10) std::abort();
			}
		}
		buf.append(buf0);
		memcpy(prefix, buf.c_str(), (buf.size()));
		//printf("%s%s",prefix, buffer);
	}
}

void EVHTTPChunkedStreamBuf::get_suffix(char* buffer, std::streamsize bytes, char *suffix, size_t suffix_len)
{
	//if (_closed_state) return;

	{
		std::string buf;
		buf.clear();
		buf.append("\r\n", 2);
		memcpy(suffix, buf.c_str(), suffix_len);
		//printf("%s------------------------------------------------------------\n",suffix);
	}
}

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

