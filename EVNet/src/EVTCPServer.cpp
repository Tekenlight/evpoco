//
//
// EVTCPServer.cpp
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
#include "Poco/Util/AbstractConfiguration.h"
#include "Poco/Util/Application.h"
#include "Poco/EVNet/EVTCPServer.h"
#include "Poco/EVNet/EVTCPServerDispatcher.h"
#include "Poco/Net/TCPServerConnection.h"
#include "Poco/EVNet/EVTCPServerConnectionFactory.h"
#include "Poco/Timespan.h"
#include "Poco/Exception.h"
#include "Poco/ErrorHandler.h"
#include "Poco/EVNet/EVTCPServerNotification.h"

#include <chunked_memory_stream.h>

using Poco::ErrorHandler;

extern "C" {
void debug_io_watcher(const char * file, const int lineno, const ev_io * w);
void debug_io_watchers(const char * file, const  int lineno, EV_P);
}

namespace Poco {
namespace EVNet {

const std::string EVTCPServer::SERVER_PREFIX_CFG_NAME("EVTCPServer.");
const std::string EVTCPServer::NUM_THREADS_CFG_NAME("numThreads");
const std::string EVTCPServer::RECV_TIME_OUT_NAME("receiveTimeOut");
const std::string EVTCPServer::NUM_CONNECTIONS_CFG_NAME("numConnections");

static void timeout_cb(EV_P_ ev_timer *w, int revents)
{
	bool ev_occurred = true;
	strms_pc_cb_ptr_type cb_ptr = (strms_pc_cb_ptr_type)0;

	if (!ev_is_active(w)) {
		return ;
	}

	cb_ptr = (strms_pc_cb_ptr_type)w->data;
	/* The below line of code essentially calls
	 * EVTCPServer::EVTCPServer::handlePeriodicWakup(const bool&)
	 */
	if (cb_ptr) ((cb_ptr->objPtr)->*(cb_ptr->method))(ev_occurred);
	return;
}

// this callback is called when data is readable on a socket
static void async_socket_cb(EV_P_ ev_io *w, int revents)
{
	bool ev_occurred = true;
	srvrs_ic_cb_ptr_type cb_ptr = (srvrs_ic_cb_ptr_type)0;
	/* for one-shot events, one must manually stop the watcher
	 * with its corresponding stop function.
	 * ev_io_stop (loop, w);
	 */
	if (!ev_is_active(w)) {
		debug_io_watcher(__FILE__,__LINE__,w);
		return ;
	}

	cb_ptr = (srvrs_ic_cb_ptr_type)w->data;
	/* The below line of code essentially calls
	 * EVTCPServer::handleConnReq(const bool)
	 */
	((cb_ptr->objPtr)->*(cb_ptr->connArrived))(ev_occurred);
	return;
}

static void async_stream_socket_cb_1(EV_P_ ev_io *w, int revents);
// this callback is called when socket is writable
static void async_stream_socket_cb_2 (EV_P_ ev_io *w, int revents)
{
	strms_ic_cb_ptr_type cb_ptr = (strms_ic_cb_ptr_type)0;
	/* for one-shot events, one must manually stop the watcher
	 * with its corresponding stop function.
	 * ev_io_stop (loop, w);
	 */
	if (!ev_is_active(w)) {
		return ;
	}

	cb_ptr = (strms_ic_cb_ptr_type)w->data;
	/* The below line of code essentially calls
	 * EVTCPServer::handleAccSocketWritable(const bool)
	 */
	ssize_t ret = 0;
	ret = ((cb_ptr->objPtr)->*(cb_ptr->socketWritable))(*(cb_ptr->ssPtr) , true);

	return;
}

// this callback is called when data is readable on a socket
static void async_stream_socket_cb_1(EV_P_ ev_io *w, int revents)
{
	if (revents & EV_WRITE) async_stream_socket_cb_2(loop, w, revents);

	if (revents & EV_READ) {
		strms_ic_cb_ptr_type cb_ptr = (strms_ic_cb_ptr_type)0;
		/* for one-shot events, one must manually stop the watcher
		 * with its corresponding stop function.
		 * ev_io_stop (loop, w);
		 */
		if (!ev_is_active(w)) {
			return ;
		}

		cb_ptr = (strms_ic_cb_ptr_type)w->data;
		/* The below line of code essentially calls
		 * EVTCPServer::handleAccSocketReadable(const bool)
		 */
		((cb_ptr->objPtr)->*(cb_ptr->dataAvailable))(*(cb_ptr->ssPtr) , true);
		// Suspending interest in events of this fd until one request is processed
		//ev_io_stop(loop, w);
		//ev_clear_pending(loop, w);
	}

	return;
}

/* This callback is to break all watchers and stop the loop. */
static void async_stop_cb_1 (struct ev_loop *loop, ev_async *w, int revents)
{
	ev_break (loop, EVBREAK_ALL);
	return;
}

/* This callback is for completion of processing of one socket. */
/* SOMETHING HAPPENED HOUTSIDE EVENT LOOP IN ANOTHER THREAD */
static void async_stop_cb_2 (struct ev_loop *loop, ev_async *w, int revents)
{
	bool ev_occurred = true;
	strms_pc_cb_ptr_type cb_ptr = (strms_pc_cb_ptr_type)0;

	if (!ev_is_active(w)) {
		return ;
	}

	cb_ptr = (strms_pc_cb_ptr_type)w->data;
	/* The below line of code essentially calls
	 * EVTCPServer::somethingHappenedInAnotherThread(const bool)
	 */
	if (cb_ptr) ((cb_ptr->objPtr)->*(cb_ptr->method))(ev_occurred);

	return;
}

//
// EVTCPServer
//

EVTCPServer::EVTCPServer(EVTCPServerConnectionFactory::Ptr pFactory, Poco::UInt16 portNumber, TCPServerParams::Ptr pParams):
	_socket(*(new ServerSocket(portNumber))),
	_thread(threadName(_socket)),
	_stopped(true),
	_loop(0),
	_ssLRUList(0,0),
	_numThreads(2),
	_numConnections(500),
	_blocking(pParams->getBlocking()),
	_pConnectionFactory(pFactory),
	_receiveTimeOut(5)
{
	Poco::Util::AbstractConfiguration& config = appConfig();
	_numThreads = config.getInt(SERVER_PREFIX_CFG_NAME + NUM_THREADS_CFG_NAME , 2);
	_receiveTimeOut = config.getInt(SERVER_PREFIX_CFG_NAME+RECV_TIME_OUT_NAME, 5);
	_numConnections = config.getInt(SERVER_PREFIX_CFG_NAME + NUM_CONNECTIONS_CFG_NAME , 500);

	Poco::ThreadPool& pool = Poco::ThreadPool::defaultPool(_numThreads,_numThreads);
	if (pParams) {
		int toAdd = pParams->getMaxThreads() - pool.capacity();
		if (toAdd > 0) pool.addCapacity(toAdd);
	}
	_pDispatcher = new EVTCPServerDispatcher(pFactory, pool, pParams, this);
	
}


EVTCPServer::EVTCPServer(EVTCPServerConnectionFactory::Ptr pFactory, const ServerSocket& socket, TCPServerParams::Ptr pParams):
	_socket(socket),
	_thread(threadName(socket)),
	_stopped(true),
	_loop(0),
	_ssLRUList(0,0),
	_numThreads(2),
	_numConnections(500),
	_blocking(pParams->getBlocking()),
	_pConnectionFactory(pFactory),
	_receiveTimeOut(5)
{
	Poco::Util::AbstractConfiguration& config = appConfig();
	_numThreads = config.getInt(SERVER_PREFIX_CFG_NAME + NUM_THREADS_CFG_NAME , 2);
	_receiveTimeOut = config.getInt(SERVER_PREFIX_CFG_NAME+RECV_TIME_OUT_NAME, 5);
	_numConnections = config.getInt(SERVER_PREFIX_CFG_NAME + NUM_CONNECTIONS_CFG_NAME , 500);

	Poco::ThreadPool& pool = Poco::ThreadPool::defaultPool(_numThreads,_numThreads);
	if (pParams) {
		int toAdd = pParams->getMaxThreads() - pool.capacity();
		if (toAdd > 0) pool.addCapacity(toAdd);
	}
	_pDispatcher = new EVTCPServerDispatcher(pFactory, pool, pParams, this);
}


EVTCPServer::EVTCPServer(EVTCPServerConnectionFactory::Ptr pFactory, Poco::ThreadPool& threadPool, const ServerSocket& socket, TCPServerParams::Ptr pParams):
	_socket(socket),
	_thread(threadName(socket)),
	_stopped(true),
	_loop(0),
	_ssLRUList(0,0),
	_numThreads(2),
	_numConnections(500),
	_blocking(pParams->getBlocking()),
	_pConnectionFactory(pFactory),
	_receiveTimeOut(5)
{
	Poco::Util::AbstractConfiguration& config = appConfig();
	_numThreads = config.getInt(SERVER_PREFIX_CFG_NAME + NUM_THREADS_CFG_NAME , 2);
	_receiveTimeOut = config.getInt(SERVER_PREFIX_CFG_NAME+RECV_TIME_OUT_NAME, 5);
	_numConnections = config.getInt(SERVER_PREFIX_CFG_NAME + NUM_CONNECTIONS_CFG_NAME , 500);

	_pDispatcher = new EVTCPServerDispatcher(pFactory, threadPool, pParams, this);
}

EVTCPServer::~EVTCPServer()
{
	try {
		stop();
		_pDispatcher->release();
		freeClear(_accssColl);
	}
	catch (...) {
		poco_unexpected();
	}
}

void EVTCPServer::freeClear( ASColMapType & amap )
{
    for ( ASColMapType::iterator it = amap.begin(); it != amap.end(); ++it ) {
        delete it->second;
    }
    amap.clear();
}

void EVTCPServer::clearAcceptedSocket(poco_socket_t fd)
{
	EVAcceptedStreamSocket *tn = _accssColl[fd];
	_accssColl.erase(fd);
	_ssLRUList.remove(tn);
	{
		ev_io * socket_watcher_ptr = 0;
		socket_watcher_ptr = tn->getSocketWatcher();
		if (socket_watcher_ptr && ev_is_active(socket_watcher_ptr)) {
			ev_io_stop(_loop, socket_watcher_ptr);
			ev_clear_pending(_loop, socket_watcher_ptr);
		}
	}
	delete tn;
}

const TCPServerParams& EVTCPServer::params() const
{
	return _pDispatcher->params();
}


void EVTCPServer::start()
{
	poco_assert (_stopped);

	_stopped = false;
	_thread.start(*this);
}

	
void EVTCPServer::stop()
{
	if (!_stopped)
	{
		_stopped = true;
		/* Calls async_stop_cb_1 */
		ev_async_send(_loop, this->stop_watcher_ptr1);
		_thread.join();
		_pDispatcher->stop();
	}
}

ssize_t EVTCPServer::sendData(StreamSocket& ss, void * chptr, size_t size)
{
	ssize_t ret = 0;
	errno = 0;
	try {
		//ret = ss.sendBytes(chptr, size , 0);
		ret = ss.sendBytes(chptr, size );
	}
	catch (...) {
		ret = -1;
	}
	if ((ret <= 0) || errno) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		}
		else {
			const char * error_string = NULL;
			if (!errno) {
				error_string = "Peer closed connection";
			}
			else {
				error_string = strerror(errno);
				//DEBUGPOINT("%s\n",error_string);
			}
			return -1;
		}
	}
	return ret;
}

ssize_t EVTCPServer::sendData(int fd, void * chptr, size_t size)
{
	ssize_t ret = 0;
	errno = 0;
	ret = send(fd, chptr, size , 0);
	if ((ret <= 0) || errno) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		}
		else {
			const char * error_string = NULL;
			if (!errno) {
				error_string = "Peer closed connection";
			}
			else {
				error_string = strerror(errno);
			}
			return -1;
		}
	}
	return ret;
}

ssize_t EVTCPServer::handleConnSocketWritable(StreamSocket & streamSocket, const bool& ev_occured)
{
	ssize_t ret = 0;
	return ret;
}

ssize_t EVTCPServer::handleAccSocketWritable(StreamSocket & streamSocket, const bool& ev_occured)
{
	ssize_t ret = 0;
	EVAcceptedStreamSocket *tn = _accssColl[streamSocket.impl()->sockfd()];
	if (!tn) return -1;
	tn->setTimeOfLastUse();
	_ssLRUList.move(tn);
	if (!tn->resDataAvlbl()) {
		goto handleAccSocketWritable_finally;
	}

	tn->setSockBusy();

	{
		chunked_memory_stream * cms = 0;

		ssize_t ret1 = 0;
		int count = 0;

		cms = tn->getResMemStream();
		void * nodeptr = 0;
		void * buffer = 0;
		size_t bytes = 0;
		nodeptr = cms->get_next(0);
		while (nodeptr) {
			count ++;
			buffer = cms->get_buffer(nodeptr);
			bytes = cms->get_buffer_len(nodeptr);

			//ret1 = sendData(streamSocket.impl()->sockfd(), buffer, bytes);
			ret1 = sendData(streamSocket, buffer, bytes);
			if (ret1 > 0) {
				cms->erase(ret1);
				nodeptr = cms->get_next(0);
				buffer = 0;
				bytes = 0;
				ret += ret1;
				ret1 = 0;
			}
			else if (ret1 == 0) {
				// Add to waiting for being write ready.
				ret = 0;
				break;
			}
			else {
				ret = -1;
				break;
			}
		}
	}

	tn->setSockFree();

handleAccSocketWritable_finally:
	if (ret >=0) {
		/* If there is more data to be sent, wait for 
		 * the socket to become writable again.
		 * */
		if (!tn->resDataAvlbl()) ret = 1;
		else ret = 0;
	}

	if (ret > 0) {
		ev_io * socket_watcher_ptr = 0;
		strms_ic_cb_ptr_type cb_ptr = 0;

		socket_watcher_ptr = tn->getSocketWatcher();

		if (tn->getState() == EVAcceptedStreamSocket::WAITING_FOR_WRITE) {
			ev_io_stop(_loop, socket_watcher_ptr);
			ev_clear_pending(_loop, socket_watcher_ptr);
			tn->setState(EVAcceptedStreamSocket::NOT_WAITING);
		}
		else if (tn->getState() == EVAcceptedStreamSocket::WAITING_FOR_READWRITE) {
			ev_io_stop(_loop, socket_watcher_ptr);
			ev_clear_pending(_loop, socket_watcher_ptr);
			ev_io_init (socket_watcher_ptr, async_stream_socket_cb_1, streamSocket.impl()->sockfd(), EV_READ);
			ev_io_start (_loop, socket_watcher_ptr);
			tn->setState(EVAcceptedStreamSocket::EVAcceptedStreamSocket::WAITING_FOR_READ);
		}
		else {
			/* It should not come here otherwise. */
			std::abort();
		}
	}
	else if (ret <0) {
		/* At this point we know that the socket has become unusable,
		 * it is possible to dispose it off and complete housekeeping.
		 * However there is a likelihood that another thread is still
		 * processing this socket, hence the disposing off must not be
		 * done over here.
		 *
		 * When the processing gets complete, and the socket is returned,
		 * At that time the socket will get disposed.
		 * */
		tn->setSockInError();
	}

	return ret;
}

ssize_t EVTCPServer::receiveData(StreamSocket & ss, void * chptr, size_t size)
{
	ssize_t ret = 0;
	errno = 0;

	try {
		//DEBUGPOINT("BEFORE SOCKET = %d\n", ss.impl()->sockfd());
		ret = ss.receiveBytes(chptr, size );
	}
	catch (std::exception & e) {
		//DEBUGPOINT("Exception %s ret = %zd\n", e.what(), ret);
	}
	if ((ret <= 0) || errno) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		}
		else {
			const char * error_string = NULL;
			if (!errno) {
				//DEBUGPOINT("ret = %zd\n", ret);
				error_string = "Peer closed connection";
			}
			else {
				error_string = strerror(errno);
			}
			return -1;
		}
	}
	return ret;
}

ssize_t EVTCPServer::receiveData(int fd, void * chptr, size_t size)
{
	ssize_t ret = 0;
	errno = 0;
	ret = recv(fd, chptr, size , 0);
	if ((ret <= 0) || errno) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		}
		else {
			const char * error_string = NULL;
			if (!errno) {
				error_string = "Peer closed connection";
			}
			else {
				error_string = strerror(errno);
			}
			return -1;
		}
	}
	return ret;
}

ssize_t EVTCPServer::handleConnSocketReadable(StreamSocket & streamSocket, const bool& ev_occured)
{
	ssize_t ret = 0;
	return ret;
}

ssize_t EVTCPServer::handleAccSocketReadable(StreamSocket & streamSocket, const bool& ev_occured)
{
	ssize_t ret = 0;
	size_t received_bytes = 0;
	EVAcceptedStreamSocket *tn = _accssColl[streamSocket.impl()->sockfd()];
	tn->setTimeOfLastUse();
	_ssLRUList.move(tn);
	tn->setSockBusy();

	{
		ssize_t ret1 = 0;
		int count = 0;
		do {
			count ++;
			void * buffer = malloc(TCP_BUFFER_SIZE);
			memset(buffer,0,TCP_BUFFER_SIZE);
			//ret1 = receiveData(streamSocket.impl()->sockfd(), buffer, TCP_BUFFER_SIZE);
			ret1 = receiveData(streamSocket, buffer, TCP_BUFFER_SIZE);
			if (ret1 >0) {
				//printf("%zd\n", ret1);
				tn->pushReqData(buffer, (size_t)ret1);
				ret += ret1;
				received_bytes += ret1;
			}
			else {
				free(buffer);
				if (ret1 < 0) {
					ret = -1;
				}
			}
		} while(!_blocking && ret1>0);
	}

handleDataAvlblOnAccSock_finally:
	if ((ret >=0) && tn->reqDataAvlbl()) {
		if (!(tn->getProcState()) ||
			(tn->getProcState()->newDataProcessed()) ||
			(!(tn->getProcState()->newDataProcessed()) && (received_bytes > 0))) {
			if (!(tn->getProcState())) {
				tn->setProcState(_pConnectionFactory->createReqProcState(this));
			}
			_pDispatcher->enqueue(tn);
			/* If data is available, and a task has been enqueued.
			 * It is not OK to cleanup the socket.
			 * It is proper to process whatever data is still there
			 * and then close the socket at a later time.
			 * */
			ret = 1;
		} 
		else {
			//DEBUGPOINT("Did not enqueue and ret = %zd\n", ret);
		}
		//DEBUGPOINT("Here %d\n", streamSocket.impl()->sockfd());
	}


	/* ret will be 0 after recv even on a tickled socket
	 * in case of SSL handshake.
	 * */
	if (ret > 0) {
		ev_io * socket_watcher_ptr = 0;
		socket_watcher_ptr = tn->getSocketWatcher();
		if (tn->getState() == EVAcceptedStreamSocket::WAITING_FOR_READ) {
			ev_io_stop(_loop, socket_watcher_ptr);
			ev_clear_pending(_loop, socket_watcher_ptr);
			tn->setState(EVAcceptedStreamSocket::NOT_WAITING);
		}
		else if (tn->getState() == EVAcceptedStreamSocket::WAITING_FOR_READWRITE) {
			ev_io_stop(_loop, socket_watcher_ptr);
			ev_clear_pending(_loop, socket_watcher_ptr);
			ev_io_init (socket_watcher_ptr, async_stream_socket_cb_1, streamSocket.impl()->sockfd(), EV_WRITE);
			ev_io_start (_loop, socket_watcher_ptr);
			tn->setState(EVAcceptedStreamSocket::EVAcceptedStreamSocket::WAITING_FOR_WRITE);
		}
		else {
			/* It should not come here otherwise. */
			DEBUGPOINT("SHOULD NOT HAVE REACHED HERE %d\n", tn->getState());
			std::abort();
		}
	}
	else if (ret < 0)  {
		if (ev_occured) {
			//DEBUGPOINT("LOSING INTEREST IN SOCKET %d\n", streamSocket.impl()->sockfd());
			clearAcceptedSocket(streamSocket.impl()->sockfd());
			//DEBUGPOINT("LOST INTEREST IN SOCKET %d\n", streamSocket.impl()->sockfd());
		}
		else {
			// If handleAccSocketReadable is called not from event loop (ev_occured = true)
			// Cleaning up of socket will lead to context being lost completely.
			// It sould be marked as being in error and the housekeeping to be done at
			// an approporiate time.
			tn->setSockInError();
		}
	}

	return ret;
}

void EVTCPServer::dataReadyForSend(int fd)
{
	/* Enque the socket */
	_queue.enqueueNotification(new EVTCPServerNotification(fd,
													EVTCPServerNotification::DATA_FOR_SEND_READY));

	/* And then wake up the loop calls async_stop_cb_2 */
	ev_async_send(_loop, this->stop_watcher_ptr2);
	return;
}

void EVTCPServer::receivedDataConsumed(int fd)
{
	/* Enque the socket */
	_queue.enqueueNotification(new EVTCPServerNotification(fd,
													EVTCPServerNotification::REQDATA_CONSUMED));

	/* And then wake up the loop calls async_stop_cb_2 */
	ev_async_send(_loop, this->stop_watcher_ptr2);
	return;
}

void EVTCPServer::errorInReceivedData(poco_socket_t fd, bool connInErr)
{
	/* Enque the socket */
	//_queue.enqueueNotification(new EVTCPServerNotification(streamSocket,fd,true));
	/* The StreamSocket Received in this function may not contain the desirable value.
	 * It could have become -1.
	 * */
	_queue.enqueueNotification(new EVTCPServerNotification(fd,
													EVTCPServerNotification::ERROR_IN_PROCESSING));

	//DEBUGPOINT("Here %d\n", fd);
	/* And then wake up the loop calls async_stop_cb_2 */
	ev_async_send(_loop, this->stop_watcher_ptr2);
	//DEBUGPOINT("Here\n");
	return;
}

void EVTCPServer::monitorDataOnAccSocket(EVAcceptedStreamSocket *tn)
{
	ev_io * socket_watcher_ptr = 0;
	if (tn->sockInError()) {
		DEBUGPOINT("RETURNING\n");
		return;
	}
	socket_watcher_ptr = tn->getSocketWatcher();
	StreamSocket ss = tn->getStreamSocket();

	{
		tn->setSockFree();
		/* If socket is not readable make it readable*/
		if ((tn->getState() == EVAcceptedStreamSocket::NOT_WAITING) ||
			 tn->getState() == EVAcceptedStreamSocket::WAITING_FOR_WRITE) {
			int events = 0;
			if (tn->getState() == EVAcceptedStreamSocket::WAITING_FOR_WRITE) {
				events = EVAcceptedStreamSocket::WAITING_FOR_READWRITE;
				tn->setState(EVAcceptedStreamSocket::WAITING_FOR_READWRITE);
			}
			else {
				events = EVAcceptedStreamSocket::WAITING_FOR_READ;
				tn->setState(EVAcceptedStreamSocket::WAITING_FOR_READ);
			}

			ev_io_stop(_loop, socket_watcher_ptr);
			ev_clear_pending(_loop, socket_watcher_ptr);
			//ev_io_set (socket_watcher_ptr, ss.impl()->sockfd(), EV_READ);
			ev_io_init(socket_watcher_ptr, async_stream_socket_cb_1, ss.impl()->sockfd(), events);
			ev_io_start (_loop, socket_watcher_ptr);
		}
	}

	if (tn->reqDataAvlbl()) {
		/* There is residual data on socket.
		 * This can be a cause for unnecessary thread context switching
		 * opportunity for optimization.
		 * */
		//DEBUGPOINT("Here\n");
		handleAccSocketReadable(ss, false);
	}

	return;
}

void EVTCPServer::sendDataOnAccSocket(EVAcceptedStreamSocket *tn)
{
	ev_io * socket_watcher_ptr = 0;
	strms_ic_cb_ptr_type cb_ptr = 0;

	socket_watcher_ptr = tn->getSocketWatcher();
	if (!socket_watcher_ptr) std::abort();

	cb_ptr = (strms_ic_cb_ptr_type)socket_watcher_ptr->data;

	/* If socket is not writable make it so. */
	if ((tn->getState() == EVAcceptedStreamSocket::NOT_WAITING) ||
		 tn->getState() == EVAcceptedStreamSocket::WAITING_FOR_READ) {
		int events = 0;
		if (tn->getState() == EVAcceptedStreamSocket::WAITING_FOR_READ) {
			events = EVAcceptedStreamSocket::WAITING_FOR_READWRITE;
			tn->setState(EVAcceptedStreamSocket::WAITING_FOR_READWRITE);
		}
		else {
			events = EVAcceptedStreamSocket::WAITING_FOR_WRITE;
			tn->setState(EVAcceptedStreamSocket::WAITING_FOR_WRITE);
		}
		cb_ptr->socketWritable = &EVTCPServer::handleAccSocketWritable;

		ev_io_stop(_loop, socket_watcher_ptr);
		ev_clear_pending(_loop, socket_watcher_ptr);
		ev_io_init (socket_watcher_ptr, async_stream_socket_cb_1, tn->getSockfd(), events);
		ev_io_start (_loop, socket_watcher_ptr);

	}

	StreamSocket ss = tn->getStreamSocket();
	handleAccSocketWritable(ss, false);

	return;
}

void EVTCPServer::somethingHappenedInAnotherThread(const bool& ev_occured)
{
	ev_io * socket_watcher_ptr = 0;
	AutoPtr<Notification> pNf = 0;
	for  (pNf = _queue.dequeueNotification(); pNf ; pNf = _queue.dequeueNotification()) {
		EVTCPServerNotification * pcNf = dynamic_cast<EVTCPServerNotification*>(pNf.get());

		EVAcceptedStreamSocket *tn = _accssColl[pcNf->sockfd()];
		if (!tn) {
			/* This should never happen. */
			DEBUGPOINT("Did not find entry in _accssColl for %d\n", pcNf->sockfd());

			/* Multiple events can get queued for a socket from another thread.
			 * In the meanwhile, it is possible that the socket gets into an error state
			 * due to various conditions, one such is wrong data format and the protocol
			 * handler fails. This condition will lead to socket getting closed.
			 * Subsequent events after closing of the socket must be ignored.
			 * */
			continue;
		}
		socket_watcher_ptr = _accssColl[pcNf->sockfd()]->getSocketWatcher();
		StreamSocket ss = tn->getStreamSocket();

		EVTCPServerNotification::what event = pcNf->getEvent();
		/* If some error has been noticed on this socket, dispose it off cleanly
		 * over here
		 * */
		if ((event == EVTCPServerNotification::REQDATA_CONSUMED) && (tn->sockInError()))
			event = EVTCPServerNotification::ERROR_IN_PROCESSING;

		switch (event) {
			case EVTCPServerNotification::REQDATA_CONSUMED:
				//DEBUGPOINT("REQDATA_CONSUMED on socket %d\n", ss.impl()->sockfd());
				if (PROCESS_COMPLETE <= (tn->getProcState()->getState())) {
					tn->deleteState();
				}
				sendDataOnAccSocket(tn);
				monitorDataOnAccSocket(tn);
				/* If processing state is present, another thread can still be processing
				 * the request, hence cannot complete housekeeping.
				 * */
				if (!tn->getProcState() && tn->sockInError())
					clearAcceptedSocket(pcNf->sockfd());
				break;
			case EVTCPServerNotification::DATA_FOR_SEND_READY:
				//DEBUGPOINT("DATA_FOR_SEND_READY on socket %d\n", ss.impl()->sockfd());
				sendDataOnAccSocket(tn);
				break;
			case EVTCPServerNotification::ERROR_IN_PROCESSING:
				//DEBUGPOINT("ERROR_IN_PROCESSING on socket %d\n", pcNf->sockfd());
				clearAcceptedSocket(pcNf->sockfd());
				break;
			default:
				break;
		}
		pcNf = NULL;
	}

	return;
}

void EVTCPServer::handleConnReq(const bool& ev_occured)
{
	ev_io * socket_watcher_ptr = 0;
	strms_ic_cb_ptr_type cb_ptr = 0;

	EVAcceptedStreamSocket * ptr = _ssLRUList.getLast();
	while (ptr && (_accssColl.size()  >= _numConnections)) {
		if (ptr->getProcState()) {
			ptr = ptr->getPrevPtr();
			continue;
		}
		ev_io_stop(_loop, ptr->getSocketWatcher());
		ev_clear_pending(_loop, ptr->getSocketWatcher());
		errorInReceivedData(ptr->getSockfd(),true);
		ptr = ptr->getPrevPtr();
	}

	int fd = 0;
	try {
		/* If the number of connections exceeds the limit this server can handle.
		 * Dont continue handling the connection.
		 * TBD: This strategy needs to be examined properly. TBD
		 * */
		StreamSocket ss = _socket.acceptConnection();
		if (_accssColl.size()  >= _numConnections) {
			return;
		}

		if (!_pConnectionFilter || _pConnectionFilter->accept(ss)) {
			// enable nodelay per default: OSX really needs that
#if defined(POCO_OS_FAMILY_UNIX)
			if (ss.address().family() != AddressFamily::UNIX_LOCAL)
#endif
			{
				ss.setNoDelay(true);
			}

			socket_watcher_ptr = (ev_io*)malloc(sizeof(ev_io));
			memset(socket_watcher_ptr,0,sizeof(ev_io));

			cb_ptr = (strms_ic_cb_ptr_type) malloc(sizeof(strms_io_cb_struct_type));
			memset(cb_ptr,0,sizeof(strms_io_cb_struct_type));

			EVAcceptedStreamSocket * acceptedSock = new EVAcceptedStreamSocket(ss);
			acceptedSock->setSocketWatcher(socket_watcher_ptr);
			fd = ss.impl()->sockfd();
			_accssColl[ss.impl()->sockfd()] = acceptedSock;
			acceptedSock->setTimeOfLastUse();
			_ssLRUList.add(acceptedSock);

			cb_ptr->objPtr = this;
			cb_ptr->dataAvailable = &EVTCPServer::handleAccSocketReadable;
			cb_ptr->ssPtr =acceptedSock->getStreamSocketPtr();
			socket_watcher_ptr->data = (void*)cb_ptr;

			acceptedSock->setState(EVAcceptedStreamSocket::WAITING_FOR_READ);

			// Make the socket non blocking.
			if (!_blocking) {
				ss.impl()->setBlocking(_blocking);
				fcntl(fd, F_SETFL, O_NONBLOCK);
			}
			/*
			{
				struct timeval tv;
				tv.tv_sec = 5;
				tv.tv_usec = 0;
				setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval));
			}
			*/
			ev_io_init (socket_watcher_ptr, async_stream_socket_cb_1, ss.impl()->sockfd(), EV_READ);
			ev_io_start (_loop, socket_watcher_ptr);
		}
	}
	catch (Poco::Exception& exc) {
		ErrorHandler::handle(exc);
	}
	catch (std::exception& exc) {
		ErrorHandler::handle(exc);
	}
	catch (...) {
		ErrorHandler::handle();
	}

	errno=0;
}

void EVTCPServer::handlePeriodicWakup(const bool& ev_occured)
{
	EVAcceptedStreamSocket *tn = 0;

	tn = _ssLRUList.getFirst();
	while (tn) {
		/* Handle all those sockets which are waiting for read while
		 * processing of input data is in progress.
		 * */
		if ((EVAcceptedStreamSocket::WAITING_FOR_READWRITE == tn->getState() ||
			EVAcceptedStreamSocket::WAITING_FOR_READ == tn->getState()) &&
			(tn->getProcState() && (tn->getProcState()->needMoreData()))) {
			struct timeval tv;
			gettimeofday(&tv,0);
			if ((tv.tv_sec - tn->getTimeOfLastUse()) > _receiveTimeOut) {
				DEBUGPOINT("TIMER EVENT OCCURED for socket %d\n", tn->getSockfd());
				ev_io_stop(_loop, tn->getSocketWatcher());
				ev_clear_pending(_loop, tn->getSocketWatcher());
				errorInReceivedData(tn->getSockfd(),true);
			}
		}
		tn= tn->getNextPtr();
	}
	return;
}

void EVTCPServer::run()
{
	ev_io socket_watcher;
	ev_async stop_watcher_1;
	ev_async stop_watcher_2;
	ev_async stop_watcher_3;
	ev_timer timeout_watcher;
	double timeout = 0.00001;

	_loop = EV_DEFAULT;
	memset(&(socket_watcher), 0, sizeof(ev_io));
	memset(&(stop_watcher_1), 0, sizeof(ev_async));
	memset(&(stop_watcher_2), 0, sizeof(ev_async));
	memset(&(stop_watcher_3), 0, sizeof(ev_async));
	memset(&(timeout_watcher), 0, sizeof(ev_timer));
	this->stop_watcher_ptr1 = &(stop_watcher_1);
	this->stop_watcher_ptr2 = &(stop_watcher_2);

	this->_cbStruct.objPtr = this;
	this->_cbStruct.connArrived = &EVTCPServer::handleConnReq;
	socket_watcher.data = (void*)&this->_cbStruct;

	/* Making the server socket non-blocking. */

	if (!_blocking) this->socket().impl()->setBlocking(_blocking);

	/* Making the server socket non-blocking. */
	ev_io_init (&(socket_watcher), async_socket_cb, this->sockfd(), EV_READ);
	ev_io_start (_loop, &(socket_watcher));

	ev_async_init (&(stop_watcher_1), async_stop_cb_1);
	ev_async_start (_loop, &(stop_watcher_1));

	{
		/* When request processing either completes or more data is required
		 * for processing. */
		strms_pc_cb_ptr_type pc_cb_ptr = (strms_pc_cb_ptr_type)0;;
		pc_cb_ptr = (strms_pc_cb_ptr_type)malloc(sizeof(strms_pc_cb_struct_type));
		pc_cb_ptr->objPtr = this;
		pc_cb_ptr->method = &EVTCPServer::somethingHappenedInAnotherThread;

		stop_watcher_2.data = (void*)pc_cb_ptr;
		ev_async_init (&(stop_watcher_2), async_stop_cb_2);
		ev_async_start (_loop, &(stop_watcher_2));
	}

	{
		strms_pc_cb_ptr_type pc_cb_ptr = (strms_pc_cb_ptr_type)0;;
		pc_cb_ptr = (strms_pc_cb_ptr_type)malloc(sizeof(strms_pc_cb_struct_type));
		pc_cb_ptr->objPtr = this;
		pc_cb_ptr->method = &EVTCPServer::handlePeriodicWakup;

		timeout_watcher.data = (void*)pc_cb_ptr;
		timeout = 5.0;
		ev_timer_init(&timeout_watcher, timeout_cb, timeout, timeout);
		ev_timer_start(_loop, &timeout_watcher);
	}

	// now wait for events to arrive
	ev_run (_loop, 0);

	free(stop_watcher_2.data);
	free(timeout_watcher.data);

	return;
}


int EVTCPServer::currentThreads() const
{
	return _pDispatcher->currentThreads();
}


int EVTCPServer::maxThreads() const
{
	return _pDispatcher->maxThreads();
}

	
int EVTCPServer::totalConnections() const
{
	return _pDispatcher->totalConnections();
}


int EVTCPServer::currentConnections() const
{
	return _pDispatcher->currentConnections();
}


int EVTCPServer::maxConcurrentConnections() const
{
	return _pDispatcher->maxConcurrentConnections();
}

	
int EVTCPServer::queuedConnections() const
{
	return _pDispatcher->queuedConnections();
}


int EVTCPServer::refusedConnections() const
{
	return _pDispatcher->refusedConnections();
}


void EVTCPServer::setConnectionFilter(const TCPServerConnectionFilter::Ptr& pConnectionFilter)
{
	poco_assert (_stopped);

	_pConnectionFilter = pConnectionFilter;
}


std::string EVTCPServer::threadName(const ServerSocket& socket)
{
#if _WIN32_WCE == 0x0800
	// Workaround for WEC2013: only the first call to getsockname()
	// succeeds. To mitigate the impact of this bug, do not call
	// socket.address(), which calls getsockname(), here.
	std::string name("EVTCPServer");
	#pragma message("Using WEC2013 getsockname() workaround in EVTCPServer::threadName(). Remove when no longer needed.")
#else
	std::string name("EVTCPServer: ");
	name.append(socket.address().toString());
#endif
	return name;

}

AbstractConfiguration& EVTCPServer::appConfig()
{
	try
	{
		return Poco::Util::Application::instance().config();
	}
	catch (Poco::NullPointerException&)
	{
		throw Poco::IllegalStateException(
			"An application configuration is required to initialize the Poco::Net::SSLManager, "
			"but no Poco::Util::Application instance is available."
		);
	}
}

//int EVTCPServer::makeTCPConnection(poco_socket_t acc_fd, Net::SocketAddress & addr, bool secure)
int EVTCPServer::makeTCPConnection(poco_socket_t acc_fd, Net::StreamSocket & css, Net::SocketAddress& addr)
{
	int ret = 0;
	ev_io * socket_watcher_ptr = 0;
	strms_ic_cb_ptr_type cb_ptr = 0;

	EVAcceptedStreamSocket *tn = _accssColl[acc_fd];

	/* There is no need to make new connections if there is
	 * no request being processed.
	 * */
	if (!(tn->getProcState())) return -1;


	try {
		css.connectNB(addr);
	} catch (Exception &e) {
		ret = -1;
	}
	if (ret < 0) return ret;

	socket_watcher_ptr = (ev_io*)malloc(sizeof(ev_io));
	memset(socket_watcher_ptr,0,sizeof(ev_io));

	EVConnectedStreamSocket * connectedSock = new EVConnectedStreamSocket(tn->getSockfd(), css);
	connectedSock->setSocketWatcher(socket_watcher_ptr);

	tn->getProcState()->setEVConnSock(connectedSock);
	connectedSock->setTimeOfLastUse();

	cb_ptr = (strms_ic_cb_ptr_type) malloc(sizeof(strms_io_cb_struct_type));
	memset(cb_ptr,0,sizeof(strms_io_cb_struct_type));

	cb_ptr->objPtr = this;
	cb_ptr->dataAvailable = &EVTCPServer::handleConnSocketReadable;
	cb_ptr->socketWritable = &EVTCPServer::handleConnSocketWritable;
	cb_ptr->ssPtr = connectedSock->getStreamSocketPtr();
	socket_watcher_ptr->data = (void*)cb_ptr;

	return ret;
}

void EVTCPServer::handleServiceRequest(const bool& ev_occured)
{
	ev_io * socket_watcher_ptr = 0;
	AutoPtr<Notification> pNf = 0;
	for  (pNf = _queue.dequeueNotification(); pNf ; pNf = _queue.dequeueNotification()) {
		EVTCPServerNotification * pcNf = dynamic_cast<EVTCPServerNotification*>(pNf.get());

		EVAcceptedStreamSocket *tn = _accssColl[pcNf->sockfd()];
		if (!tn) {
			/* This should never happen. */
			DEBUGPOINT("Did not find entry in _accssColl for %d\n", pcNf->sockfd());

			/* Multiple events can get queued for a socket from another thread.
			 * In the meanwhile, it is possible that the socket gets into an error state
			 * due to various conditions, one such is wrong data format and the protocol
			 * handler fails. This condition will lead to socket getting closed.
			 * Subsequent events after closing of the socket must be ignored.
			 * */
			continue;
		}
		socket_watcher_ptr = _accssColl[pcNf->sockfd()]->getSocketWatcher();
		StreamSocket ss = tn->getStreamSocket();

		EVTCPServerNotification::what event = pcNf->getEvent();
		/* If some error has been noticed on this socket, dispose it off cleanly
		 * over here
		 * */
		if ((event == EVTCPServerNotification::REQDATA_CONSUMED) && (tn->sockInError()))
			event = EVTCPServerNotification::ERROR_IN_PROCESSING;

		switch (event) {
			case EVTCPServerNotification::REQDATA_CONSUMED:
				//DEBUGPOINT("REQDATA_CONSUMED on socket %d\n", ss.impl()->sockfd());
				if (PROCESS_COMPLETE <= (tn->getProcState()->getState())) {
					tn->deleteState();
				}
				sendDataOnAccSocket(tn);
				monitorDataOnAccSocket(tn);
				/* If processing state is present, another thread can still be processing
				 * the request, hence cannot complete housekeeping.
				 * */
				if (!tn->getProcState() && tn->sockInError())
					clearAcceptedSocket(pcNf->sockfd());
				break;
			case EVTCPServerNotification::DATA_FOR_SEND_READY:
				//DEBUGPOINT("DATA_FOR_SEND_READY on socket %d\n", ss.impl()->sockfd());
				sendDataOnAccSocket(tn);
				break;
			case EVTCPServerNotification::ERROR_IN_PROCESSING:
				//DEBUGPOINT("ERROR_IN_PROCESSING on socket %d\n", pcNf->sockfd());
				clearAcceptedSocket(pcNf->sockfd());
				break;
			default:
				break;
		}
		pcNf = NULL;
	}

	return;
}

} } // namespace Poco::EVNet
