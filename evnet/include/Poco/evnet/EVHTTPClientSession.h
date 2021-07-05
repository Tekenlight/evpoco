//
// EVHTTPClientSession.h
//
// Library: evnet
// Package: EVHTTPClient
// Module:  EVHTTPClientSession
//
// Definition of the EVHTTPClientSession class.
//
// Copyright (c) 2019-2020, Tekenlight Solutions and contributors
//
// SPDX-License-Identifier:	BSL-1.0
//
#include <string>
#include <chunked_memory_stream.h>
#include <http_parser.h>

#include "Poco/Net/Net.h"
#include "Poco/evnet/evnet.h"
#include "Poco/Net/SocketAddress.h"
#include "Poco/Net/StreamSocket.h"
#include "Poco/Net/HTTPClientSession.h"
#include "Poco/evnet/EVHTTPResponse.h"


#ifndef Net_EVHTTPClientSession_INCLUDED
#define Net_EVHTTPClientSession_INCLUDED

namespace Poco {
namespace evnet {


class EVHTTPClientSession
{
public:
	typedef enum {
		NOT_CONNECTED=-1
		,CONNECTED
		,IN_ERROR
		,CLOSED
	} SessionState;

	EVHTTPClientSession();
	EVHTTPClientSession(Net::StreamSocket &, Net::SocketAddress &);
	~EVHTTPClientSession();

	void parser_init(EVHTTPResponse*);
	int continueRead(EVHTTPResponse& response);

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
	void setAccfd(poco_socket_t fd);
	poco_socket_t getAccfd();

private:
	poco_socket_t			_acc_fd;
	SessionState			_state;
	Net::StreamSocket		_sock;
	Net::SocketAddress		_addr;
	chunked_memory_stream*	_send_stream;
	chunked_memory_stream*	_recv_stream;
	http_parser*			_parser;

	void setRespProperties(EVHTTPResponse& response);
	int http_parser_hack();
};

inline void EVHTTPClientSession::setAccfd(poco_socket_t fd)
{
	_acc_fd = fd;
}

inline poco_socket_t EVHTTPClientSession::getAccfd()
{
	return _acc_fd;
}

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


} } // namespace Poco::evnet

#endif // Net_EVHTTPClientSession_INCLUDED
