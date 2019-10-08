//
// EVHTTPClientSession.h
//
// Library: EVNet
// Package: EVHTTPClient
// Module:  EVHTTPClientSession
//
// Definition of the EVHTTPClientSession class.
//
// Copyright (c) 2019-2020, Tekenlight Solutions and contributors
//
// SPDX-License-Identifier:	BSL-1.0
//
#include "Poco/Net/Net.h"
#include "Poco/EVNet/EVNet.h"
#include "Poco/Net/SocketAddress.h"
#include "Poco/Net/StreamSocket.h"
#include "Poco/Net/HTTPClientSession.h"


#ifndef Net_EVHTTPClientSession_INCLUDED
#define Net_EVHTTPClientSession_INCLUDED

namespace Poco {
namespace EVNet {


class EVHTTPClientSession {
public:
	typedef enum {
		NOT_CONNECTED=-1
		,CONNECTED
		,CLOSED
	} SessionState;

	EVHTTPClientSession();
	EVHTTPClientSession(Net::StreamSocket &, Net::SocketAddress &);
	~EVHTTPClientSession();

	void setSS(Net::StreamSocket&);
	void setAddr(Net::SocketAddress& );

	Net::StreamSocket& getSS();
	Net::SocketAddress& getAddr();

private:
	SessionState			_state;
	Net::StreamSocket		_sock;
	Net::SocketAddress		_addr;
};

inline Net::StreamSocket& EVHTTPClientSession::getSS()
{
	return _sock;
}

inline Net::SocketAddress& EVHTTPClientSession::getAddr()
{
	return _addr;
}

inline void EVHTTPClientSession::setSS(Net::StreamSocket& sock)
{
	_sock = sock;
}

inline void EVHTTPClientSession::setAddr(Net::SocketAddress& addr)
{
	_addr = addr;
}


} } // namespace Poco::EVNet

#endif // Net_EVHTTPClientSession_INCLUDED
