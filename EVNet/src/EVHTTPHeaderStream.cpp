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


EVHTTPHeaderStreamBuf::EVHTTPHeaderStreamBuf(EVHTTPServerSession& session, chunked_memory_stream *cms, openmode mode):
	_session(session),
	ev_buffered_stream(cms, 1024)
{
}


EVHTTPHeaderStreamBuf::~EVHTTPHeaderStreamBuf()
{
	//DEBUGPOINT("Here %p\n", _session.getServer());
	_session.getServer()->dataReadyForSend(_session.socket());
	//DEBUGPOINT("Here\n");
}

void EVHTTPHeaderStreamBuf::get_prefix(char* buffer, std::streamsize bytes, char *prefix, size_t prefix_len)
{
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


EVHTTPHeaderIOS::EVHTTPHeaderIOS(EVHTTPServerSession& session, chunked_memory_stream *cms, EVHTTPHeaderStreamBuf::openmode mode):
	_buf(session, cms, mode)
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


EVHTTPHeaderInputStream::EVHTTPHeaderInputStream(EVHTTPServerSession& session, chunked_memory_stream *cms):
	EVHTTPHeaderIOS(session, cms, std::ios::in),
	std::istream(&_buf)
{
}


EVHTTPHeaderInputStream::~EVHTTPHeaderInputStream()
{
}

//
// EVHTTPHeaderOutputStream
//


EVHTTPHeaderOutputStream::EVHTTPHeaderOutputStream(EVHTTPServerSession& session, chunked_memory_stream *cms):
	EVHTTPHeaderIOS(session, cms, std::ios::in),
	std::ostream(&_buf)
{
}


EVHTTPHeaderOutputStream::~EVHTTPHeaderOutputStream()
{
}



} } // namespace Poco::EVNet
