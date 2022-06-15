//
// EVAcceptedStreamSocket.cpp
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
#include "Poco/evnet/evnet.h"
#include "Poco/evnet/EVAcceptedStreamSocket.h"
#include "Poco/evnet/EVEventNotification.h"
#include "Poco/evnet/EVTCPServiceRequest.h"

using Poco::Net::StreamSocket;
namespace Poco{ namespace evnet {

EVAcceptedStreamSocket::EVAcceptedStreamSocket(StreamSocket & streamSocket):
	_clRdFd(-1),
	_clWrFd(-1),
	_sockFd(streamSocket.impl()->sockfd()),
	_socket_watcher(0),
	_streamSocket(streamSocket),
	_prevPtr(0),
	_nextPtr(0),
	_sockBusy(false),
	_reqProcState(0),
	_req_memory_stream(0),
	_res_memory_stream(0),
	_state(NOT_WAITING),
	_cl_state(false),
	_socketInError(0),
	_event_queue(create_ev_queue()),
	_new_active_cs_events(0),
	_base_sr_srl_num(0),
	_waiting_tobe_enqueued(false),
	_socket_upgraded_to(EVAcceptedStreamSocket::NONE),
	_shutdown_initiated(false),
	_task_type(CLIENT_REQUEST)
{
	_sock_mode = EVAcceptedStreamSocket::HTTP;
	struct timeval tv;
	gettimeofday(&tv,0);
	_timeOfLastUse = tv.tv_sec;
	_req_memory_stream = new chunked_memory_stream();
	_res_memory_stream = new chunked_memory_stream();
}

EVAcceptedStreamSocket::EVAcceptedStreamSocket(int CL_rd_fd, int CL_wr_fd):
	_clRdFd(CL_rd_fd),
	_clWrFd(CL_wr_fd),
	_sockFd(CL_rd_fd),
	_socket_watcher(0),
	_prevPtr(0),
	_nextPtr(0),
	_sockBusy(false),
	_reqProcState(0),
	_req_memory_stream(0),
	_res_memory_stream(0),
	_state(NOT_WAITING),
	_cl_state(false),
	_socketInError(0),
	_event_queue(create_ev_queue()),
	_new_active_cs_events(0),
	_base_sr_srl_num(0),
	_waiting_tobe_enqueued(false),
	_socket_upgraded_to(EVAcceptedStreamSocket::NONE),
	_shutdown_initiated(false),
	_task_type(CLIENT_REQUEST)
{
	_sock_mode = EVAcceptedStreamSocket::COMMAND_LINE_MODE;
	_out_streamSocket.setFd(CL_wr_fd);
	_streamSocket.setFd(CL_rd_fd);
	struct timeval tv;
	gettimeofday(&tv,0);
	_timeOfLastUse = tv.tv_sec;
	_req_memory_stream = new chunked_memory_stream();
	_res_memory_stream = new chunked_memory_stream();
}

EVAcceptedStreamSocket::~EVAcceptedStreamSocket()
{
	//printf("[%p:%s:%d] Here in distructor of the created socket\n",pthread_self(),__FILE__,__LINE__);
	if (this->_socket_watcher) {
		if ((void*)(this->_socket_watcher->data)) {
			free((void*)(this->_socket_watcher->data));
			this->_socket_watcher->data = NULL;
		}
		free(this->_socket_watcher);
		this->_socket_watcher = NULL;
	}
	if (this->_reqProcState) {
		delete this->_reqProcState;
		//DEBUGPOINT("Deleted g state %p for %d\n", this->_reqProcState, this->_sockFd);
		this->_reqProcState = NULL;
	}
	if (this->_req_memory_stream) {
		delete this->_req_memory_stream;
		this->_req_memory_stream = NULL;
	}
	if (this->_res_memory_stream) {
		delete this->_res_memory_stream;
		this->_res_memory_stream = NULL;
	}
	if (this->_event_queue) {
		EVEventNotification * usN = NULL;
		usN = (EVEventNotification*)dequeue(_event_queue);
		while (usN) {
			delete usN;
			usN = (EVEventNotification*)dequeue(_event_queue);
		}
		destroy_ev_queue(this->_event_queue);
		this->_event_queue = NULL;
	}
	if (this->_clRdFd != -1) {
		//DEBUGPOINT("CLOSING %d\n", this->_clRdFd);
		//close(this->_clRdFd);
	}
	if (this->_clWrFd != -1) {
		//DEBUGPOINT("CLOSING %d\n", this->_clWrFd);
		//close(this->_clRdFd);
	}
	/*
	if (this->_reservation_queue) {
		EVTCPServiceRequest * sr = NULL;
		sr = (EVTCPServiceRequest*)dequeue(_reservation_queue);
		while (sr) {
			delete sr;
			sr = (EVTCPServiceRequest*)dequeue(_event_queue);
		}
		destroy_ev_queue(this->_reservation_queue);
		this->_event_queue = NULL;
	}
	*/
}

StreamSocket &  EVAcceptedStreamSocket::getStreamSocket()
{
	return (this->_streamSocket);
}

StreamSocket &  EVAcceptedStreamSocket::getOutStreamSocket()
{
	return (this->_out_streamSocket);
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
	_timeOfLastUse = tv.tv_sec ;
	return ;
}

time_t EVAcceptedStreamSocket::getTimeOfLastUse()
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

size_t EVAcceptedStreamSocket::pushResData(void * buffer, size_t size)
{
	return _res_memory_stream->push(buffer, size);
}

size_t EVAcceptedStreamSocket::pushReqData(void * buffer, size_t size)
{
	return _req_memory_stream->push(buffer, size);
}

bool EVAcceptedStreamSocket::resDataAvlbl()
{
	int c = 0;
	return (_res_memory_stream->copy(0, &c, 1) > 0);
}

bool EVAcceptedStreamSocket::reqDataAvlbl()
{
	int c = 0;
	return (_req_memory_stream->copy(0, &c, 1) > 0);
}

} } // namespace evnet and Poco end.

