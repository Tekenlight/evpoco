//
// EVHTTPChunkedStream.h
//
// Library: EVNet
// Package: HTTP
// Module:  EVHTTPChunkedStream
//
// Definition of the EVHTTPChunkedStream class.
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#ifndef Net_EVHTTPChunkedStream_INCLUDED
#define Net_EVHTTPChunkedStream_INCLUDED


#include "Poco/Net/Net.h"
#include "Poco/MemoryPool.h"
#include <ev_buffered_stream.h>
#include <cstddef>
#include <istream>
#include <ostream>


namespace Poco {
namespace EVNet {

class Net_API EVHTTPChunkedStreamBuf: public ev_buffered_stream
	/// This is the streambuf class used for reading and writing
	/// HTTP message bodies in chunked transfer coding.
{
public:
	typedef std::basic_ios<char, std::char_traits<char>>::openmode openmode;

	EVHTTPChunkedStreamBuf(chunked_memory_stream *cms, openmode mode);
	~EVHTTPChunkedStreamBuf();
	void get_prefix(char* buffer, std::streamsize bytes, char *prefix, size_t prefix_len);
	void get_suffix(char* buffer, std::streamsize bytes, char *suffix, size_t suffix_len);
	void close();

protected:
	int readFromDevice(char* buffer, std::streamsize length);

private:
	openmode        _mode;
	std::streamsize _chunk;
	std::string     _chunkBuffer;
	static Poco::MemoryPool _pool;
	int				_closed_state;
};


class Net_API EVHTTPChunkedIOS: public virtual std::ios
	/// The base class for HTTPInputStream.
{
public:
	EVHTTPChunkedIOS(chunked_memory_stream *cms, EVHTTPChunkedStreamBuf::openmode mode);
	~EVHTTPChunkedIOS();
	EVHTTPChunkedStreamBuf* rdbuf();

protected:
	EVHTTPChunkedStreamBuf _buf;
};


class Net_API EVHTTPChunkedInputStream: public EVHTTPChunkedIOS, public std::istream
	/// This class is for internal use by Poco::Net::HTTPSession only.
{
public:
	EVHTTPChunkedInputStream(chunked_memory_stream *cms);
	~EVHTTPChunkedInputStream();
	
	/*
	void* operator new(std::size_t size);
	void operator delete(void* ptr);
	
private:
	static Poco::MemoryPool _pool;
	*/
};


class Net_API EVHTTPChunkedOutputStream: public EVHTTPChunkedIOS, public std::ostream
	/// This class is for internal use by Poco::Net::HTTPSession only.
{
public:
	EVHTTPChunkedOutputStream(chunked_memory_stream *cms);
	~EVHTTPChunkedOutputStream();

	/*
	void* operator new(std::size_t size);
	void operator delete(void* ptr);
	
private:
	static Poco::MemoryPool _pool;
	*/
};


} } // namespace Poco::Net


#endif // Net_EVHTTPChunkedStream_INCLUDED
