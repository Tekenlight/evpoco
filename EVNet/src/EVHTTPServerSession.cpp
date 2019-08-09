//
// EVHTTPServerSession.h
//
// Library: EVNet
// Package: EVHTTPServer
// Module:  EVHTTPServerSession
//
// Definition of the EVHTTPServerSession class.
//
// Copyright (c) 2018-2019, Tekenlight Solutions Pvt Ltd.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//



#include "Poco/EVNet/EVHTTPServerSession.h"

using Poco::Net::StreamSocket;
using Poco::Net::HTTPServerParams;

namespace Poco {
namespace EVNet {


EVHTTPServerSession::EVHTTPServerSession(chunked_memory_stream * mem_stream, const StreamSocket& socket, HTTPServerParams::Ptr pParams):HTTPServerSession(socket,pParams), _mem_stream(mem_stream)
{
}

EVHTTPServerSession::~EVHTTPServerSession()
{
}
				
bool EVHTTPServerSession::hasMoreRequests()
{
	return HTTPServerSession::hasMoreRequests();
}

int EVHTTPServerSession::receive(char* buffer, int length)
{
	return HTTPServerSession::receive(buffer, length);
}




} } // namespace Poco::EVNet


