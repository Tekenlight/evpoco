;//
// EVConnectedStreamSocket.h
//
// Library: evnet
// Package: EVTCPServer
// Module:  EVTCPServer
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include <ev.h>
#include <sys/time.h>
#include <chunked_memory_stream.h>
#include "Poco/Net/Net.h"
#include "Poco/Net/StreamSocket.h"

using Poco::Net::StreamSocket;

#ifndef POCO_EVNET_EVCONNECTEDSTREAMSOCKET_H_INCLUDED
#define POCO_EVNET_EVCONNECTEDSTREAMSOCKET_H_INCLUDED

namespace Poco{ namespace evnet {


class Net_API EVConnectedStreamSocket
	/// This class is acts as an element of the list of
	/// StreamSockets connected in an event driven TCP server
	///
	/// When the server makes a connection request from
	/// a server socket. A new StreamSocket is created.
	/// That along with a libev watcher for that socket
	/// are held in this object and then added to a list
	/// within the EVTCPServer.
	///
	/// When EVTCPServer itself goes out of scope all the accpted StreamSockets and the correspnding wathcers
	/// are freed.
{
public:
	typedef enum {
		BEFORE_CONNECT = -1
		,NOT_WAITING = 0
		,WAITING_FOR_READ = EV_READ
		,WAITING_FOR_WRITE = EV_WRITE
		,WAITING_FOR_READWRITE = EV_READ|EV_WRITE
	} connected_sock_state;
	EVConnectedStreamSocket(int acc_fd, StreamSocket & streamSocket);
	~EVConnectedStreamSocket();

	StreamSocket & getStreamSocket();
	/// This method gives the stored StreamSocket

	StreamSocket *  getStreamSocketPtr();
	/// This method gives a pointer to the stored StreamSocket

	ev_timer * getTimer();
	/// This method gets the socket watcher that was associated with this socket.
	
	ev_io * getSocketWatcher();
	/// This method gets the socket watcher that was associated with this socket.
	
	poco_socket_t getSockfd();
	/// This returns the socket fd of the stream socket
	/// The fd is needed to interface with libev.

	time_t getTimeOfLastUse();
	/// This returns the last time stamp when this stream socket was used for 
	/// some request processing

	void setTimeOfLastUse();
	/// This sets the last time stamp for this stream socket
	//
	
	void setSockFree();
	// Sets the _sockBusy flag to false.
	//

	void setSockBusy();
	// Sets the _sockBusy flag to true.

	size_t pushSendData(void * buffer, size_t size);
	// This will be done by the caller, i.e. an instance
	// of EVHTTPHandler class

	size_t pushRcvData(void * buffer, size_t size);
	// Transfers the bytes read from socket to the stream.
	// This will be done by Socket IO monitoring thread, whenever
	// data is received from the upstream server.

	bool sendDataAvlbl();
	bool rcvDataAvlbl();
	
	bool sockBusy();

	void setNextPtr(EVConnectedStreamSocket * ptr);
	void setPrevPtr(EVConnectedStreamSocket * ptr);
	EVConnectedStreamSocket * getNextPtr();
	EVConnectedStreamSocket * getPrevPtr();
	chunked_memory_stream * getSendMemStream();
	chunked_memory_stream * getRcvMemStream();
	void deleteState();

	void setTimer(ev_timer *timer);
	void setSocketWatcher(ev_io *socket_watcher_ptr);
	void setEventLoop(struct ev_loop* loop);
	struct ev_loop* getEventLoop();

	void setSockInError();
	bool sockInError();
	EVConnectedStreamSocket::connected_sock_state getState();
	void setState(EVConnectedStreamSocket::connected_sock_state state);
	poco_socket_t getAccSockfd();
	bool newConnection();
	void setConnectionUsed();

	void invalidateSocket();
	void makeSSCopy();
	void cleanupSocket();

private:
	poco_socket_t				_sock_fd;
	poco_socket_t				_acc_sock_fd;
	ev_io*						_socket_watcher;
	ev_timer*					_timer;
	struct ev_loop*				_loop;
	StreamSocket*				_streamSocket;
	StreamSocket				_ss;
	time_t						_timeOfLastUse;
	EVConnectedStreamSocket*	_prevPtr;
	EVConnectedStreamSocket*	_nextPtr;
	bool						_sockBusy;
	chunked_memory_stream*		_send_memory_stream;
	chunked_memory_stream*		_rcv_memory_stream;
	connected_sock_state		_state;
	int							_socketInError;
	bool						_newConnection;
};

inline void EVConnectedStreamSocket::makeSSCopy()
{
	if (!_streamSocket) {
		DEBUGPOINT("COPY CAN BE DONE ONLY WHEN SOURCE IS NOT NULL\n");
		std::abort();
	}
	_ss = *_streamSocket;
	_streamSocket = &_ss;
}

inline StreamSocket &  EVConnectedStreamSocket::getStreamSocket()
{
	return *(this->_streamSocket);
}

inline StreamSocket *  EVConnectedStreamSocket::getStreamSocketPtr()
{
	return (this->_streamSocket);
}

inline bool EVConnectedStreamSocket::newConnection()
{
	return _newConnection;
}

inline void EVConnectedStreamSocket::setConnectionUsed()
{
	_newConnection = false;
}

inline poco_socket_t EVConnectedStreamSocket::getAccSockfd()
{
	return _acc_sock_fd;
}

inline EVConnectedStreamSocket::connected_sock_state EVConnectedStreamSocket::getState()
{
	return _state;
}

inline void EVConnectedStreamSocket::setState(EVConnectedStreamSocket::connected_sock_state state)
{
	_state = state;
}


inline void EVConnectedStreamSocket::setSockInError()
{
	_socketInError = 1;
}

inline bool EVConnectedStreamSocket::sockInError()
{
	return (_socketInError>0);
}

inline void EVConnectedStreamSocket::setEventLoop(struct ev_loop* loop)
{
	_loop = loop;
}

inline struct ev_loop* EVConnectedStreamSocket::getEventLoop()
{
	return _loop;
}

inline void EVConnectedStreamSocket::invalidateSocket()
{
	_ss.setFd(POCO_INVALID_SOCKET);
}

} } // namespace evnet and Poco end.


#endif
