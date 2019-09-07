//
// EVConnectedStreamSocket.cpp
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
#include "Poco/EVNet/EVNet.h"
#include "Poco/EVNet/EVConnectedStreamSocket.h"

using Poco::Net::StreamSocket;
namespace Poco{ namespace EVNet {

EVConnectedStreamSocket::EVConnectedStreamSocket(int acc_fd, StreamSocket & streamSocket):
	_sock_fd(streamSocket.impl()->sockfd()),
	_acc_sock_fd(acc_fd),
	_socket_watcher(0),
	_streamSocket(streamSocket),
	_prevPtr(0),
	_nextPtr(0),
	_sockBusy(false),
	_req_memory_stream(0),
	_res_memory_stream(0),
	_state(BEFORE_CONNECT),
	_socketInError(0)
{
	struct timeval tv;
	gettimeofday(&tv,0);
	_timeOfLastUse = tv.tv_sec;
	_req_memory_stream = new chunked_memory_stream();
	_res_memory_stream = new chunked_memory_stream();
}

EVConnectedStreamSocket::~EVConnectedStreamSocket()
{
	//printf("[%p:%s:%d] Here in distructor of the created socket\n",pthread_self(),__FILE__,__LINE__);
	if (this->_socket_watcher) {
		if ((void*)(this->_socket_watcher->data))
			free((void*)(this->_socket_watcher->data));
		free(this->_socket_watcher);
	}
	if (this->_req_memory_stream) delete this->_req_memory_stream;
	if (this->_res_memory_stream) delete this->_res_memory_stream;
}

void EVConnectedStreamSocket::setSocketWatcher(ev_io *socket_watcher_ptr)
{
	this->_socket_watcher = socket_watcher_ptr;
}

ev_io * EVConnectedStreamSocket::getSocketWatcher()
{
	return this->_socket_watcher;
}

StreamSocket &  EVConnectedStreamSocket::getStreamSocket()
{
	return (this->_streamSocket);
}

void EVConnectedStreamSocket::setSockBusy()
{
	_sockBusy = true;
	return;
}

void EVConnectedStreamSocket::setSockFree()
{
	_sockBusy = false;
	return;
}

bool EVConnectedStreamSocket::sockBusy()
{
	return _sockBusy;
}

StreamSocket *  EVConnectedStreamSocket::getStreamSocketPtr()
{
	return &(this->_streamSocket);
}

poco_socket_t EVConnectedStreamSocket::getSockfd()
{
	return _sock_fd;
}
EVConnectedStreamSocket *  EVConnectedStreamSocket::getNextPtr()
{
	return _nextPtr;
}
EVConnectedStreamSocket *  EVConnectedStreamSocket::getPrevPtr()
{
	return _prevPtr;
}
void EVConnectedStreamSocket::setNextPtr(EVConnectedStreamSocket * ptr)
{
	_nextPtr = ptr;
}
void EVConnectedStreamSocket::setPrevPtr(EVConnectedStreamSocket * ptr)
{
	_prevPtr = ptr;
}

void  EVConnectedStreamSocket::setTimeOfLastUse()
{
	struct timeval tv;
	gettimeofday(&tv,0);
	_timeOfLastUse = tv.tv_sec ;
	return ;
}

time_t EVConnectedStreamSocket::getTimeOfLastUse()
{
	return _timeOfLastUse;
}

size_t EVConnectedStreamSocket::pushResData(void * buffer, size_t size)
{
	return _req_memory_stream->push(buffer, size);
}

size_t EVConnectedStreamSocket::pushReqData(void * buffer, size_t size)
{
	return _req_memory_stream->push(buffer, size);
}

bool EVConnectedStreamSocket::resDataAvlbl()
{
	int c = 0;
	return (_res_memory_stream->copy(0, &c, 1) > 0);
}

bool EVConnectedStreamSocket::reqDataAvlbl()
{
	int c = 0;
	return (_req_memory_stream->copy(0, &c, 1) > 0);
}

chunked_memory_stream * EVConnectedStreamSocket::getResMemStream()
{
	return _res_memory_stream;
}

chunked_memory_stream * EVConnectedStreamSocket::getReqMemStream()
{
	return _req_memory_stream;
}

} } // namespace EVNet and Poco end.

