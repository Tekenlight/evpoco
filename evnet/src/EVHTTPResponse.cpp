//
// EVHTTPResponse.cpp
//
// Library: evnet
// Package: HTTP
// Module:  EVHTTPResponse
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/evnet/evnet.h"
#include "Poco/evnet/EVHTTPResponse.h"
#include "Poco/CountingStream.h"
#include "Poco/evnet/EVHTTPHeaderStream.h"
#include "Poco/evnet/EVHTTPChunkedStream.h"
#include "Poco/evnet/EVHTTPFixedLengthStream.h"

namespace Poco {
namespace evnet {

void EVHTTPResponse::initParseState()
{
	if (_msg_parse_state) delete _msg_parse_state; _msg_parse_state = NULL;
	_msg_parse_state = new resp_msg_parse_state();
}

EVHTTPResponse::EVHTTPResponse():
	HTTPResponse(),
	_istr(0),
	_msg_parse_state(new resp_msg_parse_state())
{
}

EVHTTPResponse::~EVHTTPResponse()
{
	if (_msg_parse_state) free(_msg_parse_state); _msg_parse_state = NULL;
	if (_istr) delete _istr;
}

void EVHTTPResponse::clear()
{
	initParseState();
	HTTPResponse::clear();
}

void EVHTTPResponse::formInputStream(chunked_memory_stream * mem_inp_stream)
{
	switch (getRespType()) {
		case HTTP_HEADER_ONLY:
			_istr = new EVHTTPFixedLengthInputStream(mem_inp_stream, 0);
			break;
		case HTTP_CHUNKED:
			_istr = new EVHTTPChunkedInputStream(mem_inp_stream, this->getMessageBodySize());
			break;
		case HTTP_MULTI_PART:
		case HTTP_FIXED_LENGTH:
#if defined(POCO_HAVE_INT64)
			_istr = new EVHTTPFixedLengthInputStream(mem_inp_stream, getContentLength64());
#else
			_istr = new EVHTTPFixedLengthInputStream(mem_inp_stream, getEVContentLength());
#endif
			break;
		default:
			DEBUGPOINT("Invalid response type\n");
			std::abort();
	}
}

}
}
