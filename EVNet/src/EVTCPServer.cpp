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

using Poco::ErrorHandler;

extern "C" {
void debug_io_watcher(const char * file, const int lineno, const ev_io * w);
void debug_io_watchers(const char * file, const  int lineno, EV_P);
}

namespace Poco {
namespace EVNet {

const std::string EVTCPServer::SERVER_PREFIX_CFG_NAME("EVTCPServer.");
const std::string EVTCPServer::NUM_THREADS_CFG_NAME("numThreads");
const std::string EVTCPServer::NUM_CONNECTIONS_CFG_NAME("numConnections");


// this callback is called when data is readable on a socket
static void async_socket_cb (EV_P_ ev_io *w, int revents)
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

// this callback is called when data is readable on a socket
static void async_stream_socket_cb (EV_P_ ev_io *w, int revents)
{
	bool ev_occurred = true;
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
	 * EVTCPServer::handleDataAvlbl(const bool)
	 */
	((cb_ptr->objPtr)->*(cb_ptr->dataAvailable))(*(cb_ptr->ssPtr) , ev_occurred);

	/* Suspending interest in events of this fd until one request is processed */
	ev_io_stop(loop, w);
	ev_clear_pending(loop, w);

	return;
}

/* This callback is to break all watchers and stop the loop. */
static void async_stop_cb_1 (struct ev_loop *loop, ev_async *w, int revents)
{
	ev_break (loop, EVBREAK_ALL);
	return;
}

/* This callback is for completion of processing of one socket. */
static void async_stop_cb_2 (struct ev_loop *loop, ev_async *w, int revents)
{
	bool ev_occurred = true;
	strms_pc_cb_ptr_type cb_ptr = (strms_pc_cb_ptr_type)0;

	if (!ev_is_active(w)) {
		return ;
	}

	cb_ptr = (strms_pc_cb_ptr_type)w->data;
	/* The below line of code essentially calls
	 * EVTCPServer::reaquireSocket(const bool)
	 */
	if (cb_ptr) ((cb_ptr->objPtr)->*(cb_ptr->procComplete))(ev_occurred);

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
	_numConnections(500)
{
	Poco::Util::AbstractConfiguration& config = appConfig();
	_numThreads = config.getInt(SERVER_PREFIX_CFG_NAME + NUM_THREADS_CFG_NAME , 2);
	_numConnections = config.getInt(SERVER_PREFIX_CFG_NAME + NUM_CONNECTIONS_CFG_NAME , 500);

	reqComplEvntHandler evtHandler = {this, &EVTCPServer::reqProcComplete, &EVTCPServer::reqProcException};
	Poco::ThreadPool& pool = Poco::ThreadPool::defaultPool(_numThreads,_numThreads);
	if (pParams) {
		int toAdd = pParams->getMaxThreads() - pool.capacity();
		if (toAdd > 0) pool.addCapacity(toAdd);
	}
	_pDispatcher = new EVTCPServerDispatcher(pFactory, pool, pParams, evtHandler);
	
}


EVTCPServer::EVTCPServer(EVTCPServerConnectionFactory::Ptr pFactory, const ServerSocket& socket, TCPServerParams::Ptr pParams):
	_socket(socket),
	_thread(threadName(socket)),
	_stopped(true),
	_loop(0),
	_ssLRUList(0,0),
	_numThreads(2),
	_numConnections(500)
{
	Poco::Util::AbstractConfiguration& config = appConfig();
	_numThreads = config.getInt(SERVER_PREFIX_CFG_NAME + NUM_THREADS_CFG_NAME , 2);
	_numConnections = config.getInt(SERVER_PREFIX_CFG_NAME + NUM_CONNECTIONS_CFG_NAME , 500);

	reqComplEvntHandler evtHandler = {this, &EVTCPServer::reqProcComplete, &EVTCPServer::reqProcException};
	Poco::ThreadPool& pool = Poco::ThreadPool::defaultPool(_numThreads,_numThreads);
	if (pParams) {
		int toAdd = pParams->getMaxThreads() - pool.capacity();
		if (toAdd > 0) pool.addCapacity(toAdd);
	}
	_pDispatcher = new EVTCPServerDispatcher(pFactory, pool, pParams, evtHandler);
}


EVTCPServer::EVTCPServer(EVTCPServerConnectionFactory::Ptr pFactory, Poco::ThreadPool& threadPool, const ServerSocket& socket, TCPServerParams::Ptr pParams):
	_socket(socket),
	_thread(threadName(socket)),
	_stopped(true),
	_loop(0),
	_ssLRUList(0,0),
	_numThreads(2),
	_numConnections(500)
{
	Poco::Util::AbstractConfiguration& config = appConfig();
	_numThreads = config.getInt(SERVER_PREFIX_CFG_NAME + NUM_THREADS_CFG_NAME , 2);
	_numConnections = config.getInt(SERVER_PREFIX_CFG_NAME + NUM_CONNECTIONS_CFG_NAME , 500);

	reqComplEvntHandler evtHandler = {this, &EVTCPServer::reqProcComplete, &EVTCPServer::reqProcException};
	_pDispatcher = new EVTCPServerDispatcher(pFactory, threadPool, pParams, evtHandler);
}

EVTCPServer::~EVTCPServer()
{
	try {
		stop();
		_pDispatcher->release();
		freeClear(_ssColl);
	}
	catch (...) {
		poco_unexpected();
	}
}

void EVTCPServer::freeClear( SSColMapType & amap )
{
    for ( SSColMapType::iterator it = amap.begin(); it != amap.end(); ++it ) {
        delete it->second;
    }
    amap.clear();
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
void EVTCPServer::handleDataAvlbl(StreamSocket & streamSocket, const bool& ev_occured)
{
	EVAcceptedStreamSocket *tn = _ssColl[streamSocket.impl()->sockfd()];
	tn->setTimeOfLastUse();
	_ssLRUList.move(tn);
	tn->setSockBusy();
	//_ssLRUList.debugPrint(__FILE__,__LINE__,pthread_self());

	//printf("%s:%d:%p ref count of impl = %d\n",__FILE__,__LINE__,pthread_self(),
			//tn->getStreamSocket().impl()->referenceCount());
	_pDispatcher->enqueue(tn); //Delaying the socket allocation till it is ready for read

	return;
}

void EVTCPServer::reqProcComplete(StreamSocket & ss)
{
	/* Enque the socket */
	_queue.enqueueNotification(new EVTCPServerNotification(ss,ss.impl()->sockfd()));

	/* And then wake up the loop calls async_stop_cb_2 */
	ev_async_send(_loop, this->stop_watcher_ptr2);
	return;
}

void EVTCPServer::reqProcException(StreamSocket & streamSocket, poco_socket_t fd, bool connInErr)
{
	/* Enque the socket */
	_queue.enqueueNotification(new EVTCPServerNotification(streamSocket,fd,true));

	/* And then wake up the loop calls async_stop_cb_2 */
	ev_async_send(_loop, this->stop_watcher_ptr2);
	return;
}

void EVTCPServer::reaquireSocket(const bool& ev_occured)
{
	ev_io * socket_watcher_ptr = 0;
	AutoPtr<Notification> pNf = 0;
	for  (pNf = _queue.dequeueNotification(); pNf ; pNf = _queue.dequeueNotification()) {
		EVTCPServerNotification * pcNf = dynamic_cast<EVTCPServerNotification*>(pNf.get());

		StreamSocket ss = pcNf->socket();
		socket_watcher_ptr = _ssColl[pcNf->sockfd()]->getSocketWatcher();

		EVAcceptedStreamSocket *tn = _ssColl[pcNf->sockfd()];
		if ((fcntl (ss.impl()->sockfd(), F_GETFD) < 0)) {
			_ssColl.erase(pcNf->sockfd());
			_ssLRUList.remove(tn);
			//_ssLRUList.debugPrint(__FILE__,__LINE__,pthread_self());
			delete tn;
			continue;;
		} 
		else if (pcNf->connInError()) {
			_ssColl.erase(pcNf->sockfd());
			_ssLRUList.remove(tn);
			//_ssLRUList.debugPrint(__FILE__,__LINE__,pthread_self());
			delete tn;
			continue;;
		}

		tn->setSockFree();

		ev_clear_pending(_loop,socket_watcher_ptr);
		socket_watcher_ptr->events = 0;
		ev_io_init (socket_watcher_ptr, async_stream_socket_cb, ss.impl()->sockfd(), EV_READ);
		ev_io_start (_loop, socket_watcher_ptr);
	}

	return;
}
void EVTCPServer::handleConnReq(const bool& ev_occured)
{
	ev_io * socket_watcher_ptr = 0;
	strms_ic_cb_ptr_type cb_ptr = 0;

	while (_ssColl.size()  > _numConnections) {
		EVAcceptedStreamSocket * ptr = _ssLRUList.getLast();
		if (ptr->sockBusy()) break;
		ptr = _ssLRUList.removeLast();
		_ssColl.erase(ptr->getSockfd());

		ev_io_stop(_loop, ptr->getSocketWatcher());
		ev_clear_pending(_loop, ptr->getSocketWatcher());

		delete ptr;
	}

	int fd = 0;
	try {
		StreamSocket ss = _socket.acceptConnection();
		/* If the number of connections exceeds the limit this server can handle.
		 * Dont continue handling the connection.
		 * TBD: This strategy needs to be examined properly. TBD
		 * */
		//printf("%s:%d:%p ref count of impl = %d\n",__FILE__,__LINE__,pthread_self(),ss.impl()->referenceCount());
		if (_ssColl.size()  > _numConnections) {
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

			EVAcceptedStreamSocket * acceptedSock = new EVAcceptedStreamSocket(socket_watcher_ptr,ss);
			//printf("%s:%d:%p ref count of impl = %d\n",__FILE__,__LINE__,pthread_self(),ss.impl()->referenceCount());
			fd = ss.impl()->sockfd();
			_ssColl[ss.impl()->sockfd()] = acceptedSock;
			acceptedSock->setTimeOfLastUse();
			_ssLRUList.add(acceptedSock);

			cb_ptr->objPtr = this;
			cb_ptr->dataAvailable = &EVTCPServer::handleDataAvlbl;
			cb_ptr->ssPtr =acceptedSock->getStreamSocketPtr();
			socket_watcher_ptr->data = (void*)cb_ptr;

			ev_io_init (socket_watcher_ptr, async_stream_socket_cb, ss.impl()->sockfd(), EV_READ);
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
	
	//printf("%s:%d:%p ref count of impl = %d\n",__FILE__,__LINE__,pthread_self(),
			//_ssColl[fd]->getStreamSocket().impl()->referenceCount());
	errno=0;
}

void EVTCPServer::run()
{
	ev_io socket_watcher;
	ev_async stop_watcher_1;
	ev_async stop_watcher_2;

	strms_pc_cb_ptr_type pc_cb_ptr = (strms_pc_cb_ptr_type)0;;

	pc_cb_ptr = (strms_pc_cb_ptr_type)malloc(sizeof(strms_pc_cb_struct_type));
	pc_cb_ptr->objPtr = this;
	pc_cb_ptr->procComplete = &EVTCPServer::reaquireSocket;

	_loop = EV_DEFAULT;
	memset(&(socket_watcher), 0, sizeof(ev_io));
	memset(&(stop_watcher_1), 0, sizeof(ev_async));
	memset(&(stop_watcher_2), 0, sizeof(ev_async));
	this->stop_watcher_ptr1 = &(stop_watcher_1);
	this->stop_watcher_ptr2 = &(stop_watcher_2);

	this->_cbStruct.objPtr = this;
	this->_cbStruct.connArrived = &EVTCPServer::handleConnReq;
	socket_watcher.data = (void*)&this->_cbStruct;

	ev_io_init (&(socket_watcher), async_socket_cb, this->sockfd(), EV_READ);
	ev_io_start (_loop, &(socket_watcher));

	ev_async_init (&(stop_watcher_1), async_stop_cb_1);
	ev_async_start (_loop, &(stop_watcher_1));

	stop_watcher_2.data = (void*)pc_cb_ptr;
	ev_async_init (&(stop_watcher_2), async_stop_cb_2);
	ev_async_start (_loop, &(stop_watcher_2));

	// now wait for events to arrive
	ev_run (_loop, 0);

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


} } // namespace Poco::EVNet
