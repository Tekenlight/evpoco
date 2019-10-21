//
// EVHTTPResponse.cpp
//
// Library: EVNet
// Package: HTTP
// Module:  EVHTTPResponse
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/EVNet/EVNet.h"
#include "Poco/EVNet/EVHTTPResponse.h"
#include "Poco/CountingStream.h"
#include "Poco/EVNet/EVHTTPHeaderStream.h"
#include "Poco/EVNet/EVHTTPChunkedStream.h"
#include "Poco/EVNet/EVHTTPFixedLengthStream.h"

namespace Poco {
namespace EVNet {

void EVHTTPResponse::initParseState()
{
	if (_msg_parse_state) delete _msg_parse_state; _msg_parse_state = NULL;
	_msg_parse_state = new resp_msg_parse_state();
}

EVHTTPResponse::EVHTTPResponse():
	HTTPResponse(),
	_msg_parse_state(new resp_msg_parse_state())
{
}

EVHTTPResponse::~EVHTTPResponse()
{
	if (_msg_parse_state) free(_msg_parse_state); _msg_parse_state = NULL;
}

void EVHTTPResponse::clear()
{
	initParseState();
	HTTPResponse::clear();
}

}
}
