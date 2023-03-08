//
// MailStream.cpp
//
// Library: evnet
// Package: evnet
// Module:  EVStream
//
// Tekenlight Solutions Pvt Ltd.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/evnet/EVStream.h"


namespace Poco {
namespace evnet {


EVStreamBuf::EVStreamBuf(chunked_memory_stream *cms, openmode mode):
	ev_buffered_stream(cms, 1024)
{
	set_mode(mode);
}


EVStreamBuf::~EVStreamBuf()
{
}


EVIOS::EVIOS(chunked_memory_stream *cms, EVStreamBuf::openmode mode): _buf(cms, mode)
{
	poco_ios_init(&_buf);
}

void EVIOS::close()
{
	try {
		_buf.sync();
	}
	catch (...) {
	}
}


EVIOS::~EVIOS()
{
	try {
		_buf.sync();
	}
	catch (...) {
	}
}



EVStreamBuf* EVIOS::rdbuf()
{
	return &_buf;
}


EVInputStream::EVInputStream(chunked_memory_stream *cms): 
	EVIOS(cms, std::ios::in),
	std::istream(&_buf)
{
}


EVInputStream::~EVInputStream()
{
}


EVOutputStream::EVOutputStream(chunked_memory_stream *cms): 
	EVIOS(cms, std::ios::out),
	std::ostream(&_buf)
{
}


EVOutputStream::~EVOutputStream()
{
}


} } // namespace Poco::evnet
