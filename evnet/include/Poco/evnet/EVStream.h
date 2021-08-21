//
// EVStream.h
//
// Library: evnet
// Package: evnet
// Module:  EVStream
//
// Definition of the EVStream class.
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#ifndef evnet_EVStream_INCLUDED
#define evnet_EVStream_INCLUDED


#include <istream>
#include <ostream>
#include <ev_buffered_stream.h>

#include "Poco/StreamUtil.h"
#include "Poco/Net/Net.h"
#include "Poco/evnet/evnet.h"


namespace Poco {
namespace evnet {


class Net_API EVStreamBuf: public ev_buffered_stream
	/// The purpose of this module is to provide a mechanism for
	/// classes to use it as a stream to add generic string data
{
public:
	typedef std::basic_ios<char, std::char_traits<char>>::openmode openmode;
	EVStreamBuf(chunked_memory_stream *cms, openmode mode);
		/// Creates the EVStreamBuf and connects it

	~EVStreamBuf();
		/// Destroys the EVStreamBuf.
		
};


class Net_API EVIOS: public virtual std::ios
	/// The base class for EVInputStream and EVOutputStream.
	///
	/// This class provides common methods and is also needed to ensure 
	/// the correct initialization order of the stream buffer and base classes.
{
public:
	EVIOS(chunked_memory_stream *cms, EVStreamBuf::openmode mode);
		/// Creates the EVIOS

	~EVIOS();
		/// Destroys the stream.

	EVStreamBuf* rdbuf();
		/// Returns a pointer to the underlying streambuf.

	void close();

protected:
	EVStreamBuf _buf;
};

class Net_API EVInputStream: public EVIOS, public std::istream
{
public:
	EVInputStream(chunked_memory_stream *cms);

	~EVInputStream();
};


class Net_API EVOutputStream: public EVIOS, public std::ostream
{
public:
	EVOutputStream(chunked_memory_stream *cms);

	~EVOutputStream();
};


} } // namespace Poco::evnet


#endif // evnet_EVStream_INCLUDED
