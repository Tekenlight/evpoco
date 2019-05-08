//
// EVAcceptedStreamSocket.cpp
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
#include "Poco/EVNet/EVAcceptedStreamSocket.h"

using Poco::Net::StreamSocket;
namespace Poco{ namespace EVNet {

EVAcceptedStreamSocket::EVAcceptedStreamSocket(ev_io *libevSocketWatcherPtr, StreamSocket & streamSocket):
	_sockFd(streamSocket.impl()->sockfd()),
	_libevSocketWatcherPtr(libevSocketWatcherPtr),
	_streamSocket(streamSocket),
	_prevPtr(0),
	_nextPtr(0),
	_sockBusy(false),
	_reqProcState(0)
{
	struct timeval tv;
	gettimeofday(&tv,0);
	_timeOfLastUse = tv.tv_sec * 1000000 + tv.tv_usec;
}

EVAcceptedStreamSocket::~EVAcceptedStreamSocket()
{
	//printf("[%p:%s:%d] Here in distructor of the created socket\n",pthread_self(),__FILE__,__LINE__);
	if (this->_libevSocketWatcherPtr) {
		if ((void*)(this->_libevSocketWatcherPtr->data))
			free((void*)(this->_libevSocketWatcherPtr->data));
		free(this->_libevSocketWatcherPtr);
	}
	if (this->_reqProcState) delete _reqProcState;
}
StreamSocket &  EVAcceptedStreamSocket::getStreamSocket()
{
	return (this->_streamSocket);
}

void EVAcceptedStreamSocket::setSockBusy()
{
	_sockBusy = true;
	return;
}

void EVAcceptedStreamSocket::setSockFree()
{
	_sockBusy = false;
	return;
}

bool EVAcceptedStreamSocket::sockBusy()
{
	return _sockBusy;
}

StreamSocket *  EVAcceptedStreamSocket::getStreamSocketPtr()
{
	return &(this->_streamSocket);
}
ev_io * EVAcceptedStreamSocket::getSocketWatcher()
{
	return (this->_libevSocketWatcherPtr);
}
poco_socket_t EVAcceptedStreamSocket::getSockfd()
{
	return _sockFd;
}
EVAcceptedStreamSocket *  EVAcceptedStreamSocket::getNextPtr()
{
	return _nextPtr;
}
EVAcceptedStreamSocket *  EVAcceptedStreamSocket::getPrevPtr()
{
	return _prevPtr;
}
void EVAcceptedStreamSocket::setNextPtr(EVAcceptedStreamSocket * ptr)
{
	_nextPtr = ptr;
}
void EVAcceptedStreamSocket::setPrevPtr(EVAcceptedStreamSocket * ptr)
{
	_prevPtr = ptr;
}

void  EVAcceptedStreamSocket::setTimeOfLastUse()
{
	struct timeval tv;
	gettimeofday(&tv,0);
	_timeOfLastUse = tv.tv_sec * 1000000 + tv.tv_usec;
	return ;
}

long long  EVAcceptedStreamSocket::getTimeOfLastUse()
{
	return _timeOfLastUse;
}

void EVAcceptedStreamSocket::setProcState(EVProcessingState* procState)
{
	_reqProcState = procState;
}

EVProcessingState* EVAcceptedStreamSocket::getProcState()
{
	return _reqProcState;
}

void EVAcceptedStreamSocket::deleteState()
{
	delete _reqProcState;
	_reqProcState = NULL;
	return;
}


} } // namespace EVNet and Poco end.

