//
// EVConnectedStreamSocket.cpp
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

#include <evpoco/ev.h>
#include <sys/time.h>
#include "Poco/evnet/evnet.h"
#include "Poco/evnet/EVConnectedStreamSocket.h"

using Poco::Net::StreamSocket;
namespace Poco{ namespace evnet {

EVConnectedStreamSocket::EVConnectedStreamSocket(int acc_fd, StreamSocket & streamSocket):
	_sock_fd(streamSocket.impl()->sockfd()),
	_acc_sock_fd(acc_fd),
	_socket_watcher(0),
	_timer(0),
	_streamSocket(&streamSocket),
	_prevPtr(0),
	_nextPtr(0),
	_sockBusy(false),
	_send_memory_stream(0),
	_rcv_memory_stream(0),
	_state(BEFORE_CONNECT),
	_socketInError(0),
	_newConnection(true)
{
	struct timeval tv;
	gettimeofday(&tv,0);
	_timeOfLastUse = tv.tv_sec;
	_send_memory_stream = new chunked_memory_stream();
	_rcv_memory_stream = new chunked_memory_stream();
}

void EVConnectedStreamSocket::cleanupSocket()
{
	this->invalidateSocket();
	if (this->_socket_watcher) {
		ev_io_stop(this->_loop, this->_socket_watcher);
		if ((void*)(this->_socket_watcher->data)) {
			free((void*)(this->_socket_watcher->data));
			this->_socket_watcher->data = NULL;
		}
		free(this->_socket_watcher);
		this->_socket_watcher = NULL;
	}
	if (this->_timer) {
		ev_timer_stop(this->_loop, this->_timer);
		if ((void*)(this->_timer->data)) {
			free((void*)(this->_timer->data));
			this->_timer->data = NULL;
		}
		free(this->_timer);
		this->_timer = NULL;
	}
}

EVConnectedStreamSocket::~EVConnectedStreamSocket()
{
	//DEBUGPOINT("Cleaning up [%d]\n", this->getSockfd());
	this->invalidateSocket();
	if (this->_socket_watcher) {
		ev_io_stop(this->_loop, this->_socket_watcher);
		if ((void*)(this->_socket_watcher->data)) {
			free((void*)(this->_socket_watcher->data));
			this->_socket_watcher->data = NULL;
		}
		free(this->_socket_watcher);
		this->_socket_watcher = NULL;
	}
	if (this->_timer) {
		ev_timer_stop(this->_loop, this->_timer);
		if ((void*)(this->_timer->data)) {
			free((void*)(this->_timer->data));
			this->_timer->data = NULL;
		}
		free(this->_timer);
		this->_timer = NULL;
	}
	if (this->_send_memory_stream) {
		delete this->_send_memory_stream;
		this->_send_memory_stream = NULL;
	}
	if (this->_rcv_memory_stream) {
		delete this->_rcv_memory_stream;
		this->_rcv_memory_stream = NULL;
	}
}

void EVConnectedStreamSocket::setTimer(ev_timer *timer)
{
	if (this->_timer) {
		ev_timer_stop(this->_loop, this->_timer);
		if ((void*)(this->_timer->data)) {
			free((void*)(this->_timer->data));
			this->_timer->data = NULL;
		}
		free(this->_timer);
		this->_timer = NULL;
	}
	this->_timer = timer;
}

void EVConnectedStreamSocket::setSocketWatcher(ev_io *socket_watcher_ptr)
{
	if (this->_socket_watcher) {
		ev_io_stop(this->_loop, this->_socket_watcher);
		if ((void*)(this->_socket_watcher->data)) {
			free((void*)(this->_socket_watcher->data));
			this->_socket_watcher->data = NULL;
		}
		free(this->_socket_watcher);
		this->_socket_watcher = NULL;
	}
	this->_socket_watcher = socket_watcher_ptr;
}

ev_timer * EVConnectedStreamSocket::getTimer()
{
	return this->_timer;
}

ev_io * EVConnectedStreamSocket::getSocketWatcher()
{
	return this->_socket_watcher;
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

size_t EVConnectedStreamSocket::pushRcvData(void * buffer, size_t size)
{
	return _rcv_memory_stream->push(buffer, size);
}

size_t EVConnectedStreamSocket::pushSendData(void * buffer, size_t size)
{
	return _send_memory_stream->push(buffer, size);
}

bool EVConnectedStreamSocket::sendDataAvlbl()
{
	int c = 0;
	return (_send_memory_stream->copy(0, &c, 1) > 0);
}

bool EVConnectedStreamSocket::rcvDataAvlbl()
{
	int c = 0;
	return (_rcv_memory_stream->copy(0, &c, 1) > 0);
}

chunked_memory_stream * EVConnectedStreamSocket::getRcvMemStream()
{
	return _rcv_memory_stream;
}

chunked_memory_stream * EVConnectedStreamSocket::getSendMemStream()
{
	return _send_memory_stream;
}

} } // namespace evnet and Poco end.

