//
// EVHTTPStream.h
//
// Library: EVNet
// Package: HTTP
// Module:  EVHTTPStream
//
// Definition of the EVHTTPStream class.
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#ifndef EVNet_EVHTTPStream_INCLUDED
#define EVNet_EVHTTPStream_INCLUDED


#include "Poco/StreamUtil.h"
#include "Poco/Net/Net.h"
#include "Poco/Net/HTTPSession.h"
#include "Poco/EVNet/EVNet.h"
#include "Poco/MemoryPool.h"
#include <ev_buffered_stream.h>
#include <chunked_memory_stream.h>
#include <cstddef>
#include <istream>
#include <ostream>

using Poco::Net::HTTPSession;

namespace Poco {
namespace EVNet {


class HTTPSession;


class Net_API EVHTTPStreamBuf: public ev_buffered_stream
	/// This is the streambuf class used for reading and writing
	/// HTTP message bodies.
{
public:
	typedef std::basic_ios<char, std::char_traits<char>>::openmode openmode;
	EVHTTPStreamBuf(chunked_memory_stream *, openmode mode);
	~EVHTTPStreamBuf();
	void close();

private:
	openmode     _mode;
};


class Net_API EVHTTPIOS: public virtual std::ios
	/// The base class for EVHTTPInputStream.
{
public:
	EVHTTPIOS(chunked_memory_stream *cms, EVHTTPStreamBuf::openmode mode);
	~EVHTTPIOS();
	EVHTTPStreamBuf* rdbuf();

protected:
	EVHTTPStreamBuf _buf;
};


class Net_API EVHTTPInputStream: public EVHTTPIOS, public std::istream
	/// This class is for internal use by HTTPSession only.
{
public:
	EVHTTPInputStream(chunked_memory_stream *cms);
	~EVHTTPInputStream();

};


class Net_API EVHTTPOutputStream: public EVHTTPIOS, public std::ostream
	/// This class is for internal use by HTTPSession only.
{
public:
	EVHTTPOutputStream(chunked_memory_stream *cms);
	~EVHTTPOutputStream();

};


} } // namespace Poco::EVNet


#endif // EVNet_EVHTTPStream_INCLUDED
