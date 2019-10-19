//
// EVHTTPRequest.h
//
// Library: EVNet
// Package: HTTPServer
// Module:  EVHTTPRequest
//
// Definition of the EVHTTPRequest class.
//
// Copyright (c) 2019-2020, Tekenlight Solutions Pvt Ltd.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//

#ifndef EVNet_EVHTTPRequest_INCLUDED
#define EVNet_EVHTTPRequest_INCLUDED

#include <ostream>
#include <chunked_memory_stream.h>
#include "Poco/EVNet/EVNet.h"
#include "Poco/Net/HTTPRequest.h"

namespace Poco {
namespace EVNet {

class Net_API EVHTTPRequest: public Net::HTTPRequest
	/// This subclass of HTTPRequest is used for
	/// representing client-side HTTP requests.
	///
{
public:
	EVHTTPRequest();
		/// Creates a GET / HTTP/1.1 HTTP request.

	EVHTTPRequest(const std::string& method, const std::string& uri);
		/// Creates a HTTP/1.1 request with the given method and URI.
	
	std::ostream* getRequestStream();
	void prepareHeaderForSend();

	chunked_memory_stream* getMessageHeader();
	chunked_memory_stream* getMessageBody();

	~EVHTTPRequest();

private:
	chunked_memory_stream*		_msg_header;
	chunked_memory_stream*		_msg_body;
	std::ostream*				_msg_body_stream;


};

} } 

#endif // EVNet_EVHTTPRequest_INCLUDED
