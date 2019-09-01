//
// EVAcceptedStreamSocket.h
//
// Library: EVNet
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
#include "Poco/EVNet/EVProcessingState.h"

using Poco::Net::StreamSocket;

#ifndef POCO_EVNET_EVACCEPTEDSTREAMSOCKET_H_INCLUDED
#define POCO_EVNET_EVACCEPTEDSTREAMSOCKET_H_INCLUDED

namespace Poco{ namespace EVNet {


class Net_API EVAcceptedStreamSocket
	/// This class is acts as an element of the list of
	/// StreamSockets opened in an event driven TCP server
	///
	/// When the server accepts a connection request from
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
		NOT_WAITING = 0
		,WAITING_FOR_READ = EV_READ
		,WAITING_FOR_WRITE = EV_WRITE
		,WAITING_FOR_READWRITE = EV_READ|EV_WRITE
	} accepted_sock_state;
	EVAcceptedStreamSocket(StreamSocket & streamSocket);
	~EVAcceptedStreamSocket();

	StreamSocket & getStreamSocket();
	/// This method gives the stored StreamSocket

	StreamSocket *  getStreamSocketPtr();
	/// This method gives a pointer to the stored StreamSocket

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
	// Sets the _sockBusy glag to false.
	//
	
	void setSockBusy();
	// Sets the _sockBusy glag to true.

	size_t pushReqData(void * buffer, size_t size);
	size_t pushResData(void * buffer, size_t size);
	// Transfers the bytes read from socket to the stream.

	bool reqDataAvlbl();
	bool resDataAvlbl();
	
	bool sockBusy();

	void setProcState(EVProcessingState* procState);

	EVProcessingState* getProcState();

	void setNextPtr(EVAcceptedStreamSocket * ptr);
	void setPrevPtr(EVAcceptedStreamSocket * ptr);
	EVAcceptedStreamSocket * getNextPtr();
	EVAcceptedStreamSocket * getPrevPtr();
	chunked_memory_stream * getReqMemStream();
	chunked_memory_stream * getResMemStream();
	void deleteState();

	void setSocketReadWatcher(ev_io *socket_watcher_ptr);
	ev_io * getSocketReadWatcher();

	accepted_sock_state getState();
	void setState(accepted_sock_state state);
	inline void setSockInError();
	inline bool sockInError();

private:
	poco_socket_t				_sockFd;
	ev_io*						_socket_read_watcher;
	StreamSocket				_streamSocket;
	time_t						_timeOfLastUse;
	EVAcceptedStreamSocket*		_prevPtr;
	EVAcceptedStreamSocket*		_nextPtr;
	bool						_sockBusy;
	EVProcessingState*			_reqProcState;
	chunked_memory_stream*		_req_memory_stream;
	chunked_memory_stream*		_res_memory_stream;
	accepted_sock_state			_state;
	int							_socketInError;
};

inline EVAcceptedStreamSocket::accepted_sock_state EVAcceptedStreamSocket::getState()
{
	return _state;
}

inline void EVAcceptedStreamSocket::setState(EVAcceptedStreamSocket::accepted_sock_state state)
{
	_state = state;
}

inline void EVAcceptedStreamSocket::setSockInError()
{
	_socketInError = 1;
}

inline bool EVAcceptedStreamSocket::sockInError()
{
	return (_socketInError>0);
}

} } // namespace EVNet and Poco end.


#endif
