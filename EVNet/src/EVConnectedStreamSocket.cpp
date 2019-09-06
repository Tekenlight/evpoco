//
// ECConnectedStreamSocket.cpp
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
#include "Poco/EVNet/ECConnectedStreamSocket.h"

using Poco::Net::StreamSocket;
namespace Poco{ namespace EVNet {

ECConnectedStreamSocket::ECConnectedStreamSocket(StreamSocket & streamSocket):
	_sockFd(streamSocket.impl()->sockfd()),
	_socket_watcher(0),
	_streamSocket(streamSocket),
	_prevPtr(0),
	_nextPtr(0),
	_sockBusy(false),
	_req_memory_stream(0),
	_res_memory_stream(0),
	_state(NOT_WAITING),
	_socketInError(0)
{
	struct timeval tv;
	gettimeofday(&tv,0);
	_timeOfLastUse = tv.tv_sec;
	_req_memory_stream = new chunked_memory_stream();
	_res_memory_stream = new chunked_memory_stream();
}

ECConnectedStreamSocket::~ECConnectedStreamSocket()
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

void ECConnectedStreamSocket::setSocketWatcher(ev_io *socket_watcher_ptr)
{
	this->_socket_watcher = socket_watcher_ptr;
}

ev_io * ECConnectedStreamSocket::getSocketWatcher()
{
	return this->_socket_watcher;
}

StreamSocket &  ECConnectedStreamSocket::getStreamSocket()
{
	return (this->_streamSocket);
}

void ECConnectedStreamSocket::setSockBusy()
{
	_sockBusy = true;
	return;
}

void ECConnectedStreamSocket::setSockFree()
{
	_sockBusy = false;
	return;
}

bool ECConnectedStreamSocket::sockBusy()
{
	return _sockBusy;
}

StreamSocket *  ECConnectedStreamSocket::getStreamSocketPtr()
{
	return &(this->_streamSocket);
}

poco_socket_t ECConnectedStreamSocket::getSockfd()
{
	return _sockFd;
}
ECConnectedStreamSocket *  ECConnectedStreamSocket::getNextPtr()
{
	return _nextPtr;
}
ECConnectedStreamSocket *  ECConnectedStreamSocket::getPrevPtr()
{
	return _prevPtr;
}
void ECConnectedStreamSocket::setNextPtr(ECConnectedStreamSocket * ptr)
{
	_nextPtr = ptr;
}
void ECConnectedStreamSocket::setPrevPtr(ECConnectedStreamSocket * ptr)
{
	_prevPtr = ptr;
}

void  ECConnectedStreamSocket::setTimeOfLastUse()
{
	struct timeval tv;
	gettimeofday(&tv,0);
	_timeOfLastUse = tv.tv_sec ;
	return ;
}

time_t ECConnectedStreamSocket::getTimeOfLastUse()
{
	return _timeOfLastUse;
}

size_t ECConnectedStreamSocket::pushResData(void * buffer, size_t size)
{
	return _req_memory_stream->push(buffer, size);
}

size_t ECConnectedStreamSocket::pushReqData(void * buffer, size_t size)
{
	return _req_memory_stream->push(buffer, size);
}

bool ECConnectedStreamSocket::resDataAvlbl()
{
	int c = 0;
	return (_res_memory_stream->copy(0, &c, 1) > 0);
}

bool ECConnectedStreamSocket::reqDataAvlbl()
{
	int c = 0;
	return (_req_memory_stream->copy(0, &c, 1) > 0);
}

chunked_memory_stream * ECConnectedStreamSocket::getResMemStream()
{
	return _res_memory_stream;
}

chunked_memory_stream * ECConnectedStreamSocket::getReqMemStream()
{
	return _req_memory_stream;
}

} } // namespace EVNet and Poco end.

