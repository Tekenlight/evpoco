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

EVHTTPResponse::EVHTTPResponse()
{
}

EVHTTPResponse::~EVHTTPResponse()
{
}

}
}
