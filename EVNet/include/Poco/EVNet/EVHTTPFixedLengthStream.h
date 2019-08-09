//
// HTTPFixedLengthStream.h
//
// Library: EVNet
// Package: HTTP
// Module:  EVHTTPFixedLengthStream
//
// Definition of the EVHTTPFixedLengthStream class.
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#ifndef EVNet_HTTPFixedLengthStream_INCLUDED
#define EVNet_HTTPFixedLengthStream_INCLUDED


#include "Poco/Net/Net.h"
#include "Poco/EVNet/EVNet.h"
#include "Poco/MemoryPool.h"
#include <cstddef>
#include <istream>
#include <ostream>
#include <ev_buffered_stream.h>


namespace Poco {
namespace EVNet {


class Net_API EVHTTPFixedLengthStreamBuf: public ev_buffered_stream
	/// This is the streambuf class used for reading and writing fixed-size
	/// HTTP message bodies.
	///
	/// At most a given number of bytes are read or written.
{
public:

#if defined(POCO_HAVE_INT64)
	typedef Poco::Int64 ContentLength;
#else
	typedef std::streamsize ContentLength;
#endif

	typedef std::basic_ios<char, std::char_traits<char>>::openmode openmode;

	EVHTTPFixedLengthStreamBuf(chunked_memory_stream *, ContentLength length, openmode mode);
	~EVHTTPFixedLengthStreamBuf();
	
};


class Net_API EVHTTPFixedLengthIOS: public virtual std::ios
	/// The base class for EVHTTPFixedLengthInputStream.
{
public:
	EVHTTPFixedLengthIOS(chunked_memory_stream *cms, EVHTTPFixedLengthStreamBuf::ContentLength length, EVHTTPFixedLengthStreamBuf::openmode mode);
	~EVHTTPFixedLengthIOS();
	EVHTTPFixedLengthStreamBuf* rdbuf();

protected:
	EVHTTPFixedLengthStreamBuf _buf;
};


class Net_API EVHTTPFixedLengthInputStream: public EVHTTPFixedLengthIOS, public std::istream
{
public:
	EVHTTPFixedLengthInputStream(chunked_memory_stream *cms, EVHTTPFixedLengthStreamBuf::ContentLength length);
	~EVHTTPFixedLengthInputStream();
	
	void* operator new(std::size_t size);
	void operator delete(void* ptr);
	
private:
	static Poco::MemoryPool _pool;
};


/*
class Net_API HTTPFixedLengthOutputStream: public EVHTTPFixedLengthIOS, public std::ostream
	/// This class is for internal use by HTTPSession only.
{
public:
	HTTPFixedLengthOutputStream(HTTPSession& session, EVHTTPFixedLengthStreamBuf::ContentLength length);
	~HTTPFixedLengthOutputStream();

	void* operator new(std::size_t size);
	void operator delete(void* ptr);
	
private:
	static Poco::MemoryPool _pool;
};

*/

} } // namespace Poco::EVNet


#endif // EVNet_HTTPFixedLengthStream_INCLUDED
