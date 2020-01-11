//
// EVHTTPHeaderStream.h
//
// Library: evnet
// Package: HTTP
// Module:  EVHTTPHeaderStream
//
// Definition of the EVHTTPHeaderStream class.
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#ifndef EVNet_EVHTTPHeaderStream_INCLUDED
#define EVNet_EVHTTPHeaderStream_INCLUDED


#include "Poco/Net/Net.h"
#include "Poco/evnet/evnet.h"
#include "Poco/evnet/EVServer.h"
#include "Poco/evnet/EVHTTPServerSession.h"
#include "Poco/MemoryPool.h"
#include <cstddef>
#include <istream>
#include <ostream>

#include <chunked_memory_stream.h>
#include <ev_buffered_stream.h>

namespace Poco {
namespace evnet {


class Net_API EVHTTPHeaderStreamBuf: public ev_buffered_stream
	/// This is the streambuf class used for reading from a HTTP header
	/// in a HTTPSession.
{
public:
	typedef std::basic_ios<char, std::char_traits<char>>::openmode openmode;

	EVHTTPHeaderStreamBuf(chunked_memory_stream *cms, openmode mode);
	void get_prefix(char* buffer, std::streamsize bytes, char *prefix, size_t prefix_len);
	~EVHTTPHeaderStreamBuf();

};


class Net_API EVHTTPHeaderIOS: public virtual std::ios
	/// The base class for EVHTTPHeaderInputStream.
{
public:
	EVHTTPHeaderIOS(chunked_memory_stream *cms, EVHTTPHeaderStreamBuf::openmode mode);
	~EVHTTPHeaderIOS();
	EVHTTPHeaderStreamBuf* rdbuf();

protected:
	EVHTTPHeaderStreamBuf _buf;
};


class Net_API EVHTTPHeaderInputStream: public EVHTTPHeaderIOS, public std::istream
	/// This class is for internal use by HTTPSession only.
{
public:
	EVHTTPHeaderInputStream(chunked_memory_stream * cms);
	~EVHTTPHeaderInputStream();

};


class Net_API EVHTTPHeaderOutputStream: public EVHTTPHeaderIOS, public std::ostream
	/// This class is for internal use by HTTPSession only.
{
public:
	EVHTTPHeaderOutputStream(chunked_memory_stream * cms);
	~EVHTTPHeaderOutputStream();

};


} } // namespace Poco::evnet


#endif // Net_EVHTTPHeaderStream_INCLUDED
