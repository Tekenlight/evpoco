//
// EVHTTPResponse.h
//
// Library: EVNet
// Package: HTTPServer
// Module:  EVHTTPResponse
//
// Definition of the EVHTTPResponse class.
//
// Copyright (c) 2019-2020, Tekenlight Solutions Pvt Ltd.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//

#ifndef EVNet_EVHTTPResponse_INCLUDED
#define EVNet_EVHTTPResponse_INCLUDED

#include <istream>
#include <chunked_memory_stream.h>
#include "Poco/EVNet/EVNet.h"
#include "Poco/Net/HTTPResponse.h"

namespace Poco {
namespace EVNet {

class Net_API EVHTTPResponse: public Net::HTTPResponse
	/// This subclass of HTTPResponse is used for
	/// representing client-side HTTP requests.
	///
{
public:
	EVHTTPResponse();
	~EVHTTPResponse();

private:

};

} } 

#endif // EVNet_EVHTTPResponse_INCLUDED
