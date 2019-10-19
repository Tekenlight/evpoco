//
// EVHTTPClientSession.cpp
//
// Library: EVNet
// Package: EVHTTPClient
// Module:  EVHTTPClientSession
//
// Copyright (c) 2019-2020, Tekenlight Solutions and contributors
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/EVNet/EVHTTPClientSession.h"

namespace Poco {
namespace EVNet {

EVHTTPClientSession::EVHTTPClientSession(Net::StreamSocket& sock, Net::SocketAddress &addr):
	_sock(sock),
	_addr(addr),
	_state(NOT_CONNECTED),
	_send_stream(0),
	_recv_stream(0)
{
}

EVHTTPClientSession::EVHTTPClientSession():
	_state(NOT_CONNECTED),
	_send_stream(0),
	_recv_stream(0)
{
}

EVHTTPClientSession::~EVHTTPClientSession()
{
}

} } // namespace Poco::EVNet
