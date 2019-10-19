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
#include <chunked_memory_stream.h>
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
		,ERROR
		,CLOSED
	} SessionState;

	EVHTTPClientSession();
	EVHTTPClientSession(Net::StreamSocket &, Net::SocketAddress &);
	~EVHTTPClientSession();

	void setSS(Net::StreamSocket&);
	void setAddr(Net::SocketAddress& );
	
	void setState(SessionState);
	SessionState getState();

	Net::StreamSocket& getSS();
	Net::SocketAddress& getAddr();

	void setRecvStream(chunked_memory_stream *cms);
	chunked_memory_stream* getRecvStream();
	void setSendStream(chunked_memory_stream *cms);
	chunked_memory_stream* getSendStream();

private:
	SessionState			_state;
	Net::StreamSocket		_sock;
	Net::SocketAddress		_addr;
	chunked_memory_stream*	_send_stream;
	chunked_memory_stream*	_recv_stream;
};

inline void EVHTTPClientSession::setRecvStream(chunked_memory_stream *cms)
{
	_recv_stream = cms;
}

inline chunked_memory_stream* EVHTTPClientSession::getRecvStream()
{
	return _recv_stream;
}

inline void EVHTTPClientSession::setSendStream(chunked_memory_stream *cms)
{
	_send_stream = cms;
}

inline chunked_memory_stream* EVHTTPClientSession::getSendStream()
{
	return _send_stream;
}

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

inline void EVHTTPClientSession::setState(EVHTTPClientSession::SessionState s)
{
	_state = s;
}

inline EVHTTPClientSession::SessionState EVHTTPClientSession::getState()
{
	return _state;
}


} } // namespace Poco::EVNet

#endif // Net_EVHTTPClientSession_INCLUDED
