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


#include <sys/time.h>
#include <sys/socket.h>

#include <ev.h>
#include <ef_io.h>

#include "Poco/evnet/evnet.h"
#include "Poco/Util/AbstractConfiguration.h"
#include "Poco/Util/Application.h"
#include "Poco/evnet/EVTCPServer.h"
#include "Poco/evnet/EVTCPServerDispatcher.h"
#include "Poco/Net/TCPServerConnection.h"
#include "Poco/evnet/EVTCPServerConnectionFactory.h"
#include "Poco/Timespan.h"
#include "Poco/Exception.h"
#include "Poco/ErrorHandler.h"
#include "Poco/evnet/EVTCPServerNotification.h"

using Poco::ErrorHandler;

extern "C" {
void debug_io_watcher(const char * file, const int lineno, const ev_io * w);
void debug_io_watchers(const char * file, const  int lineno, EV_P);
}

namespace Poco {
namespace evnet {

typedef struct _raw_data_s {
	_raw_data_s() {
		this->data = NULL;
		this->size = 0;
	}
	~_raw_data_s() {
		if (this->data) free(this->data);
	}
	void * data;
	size_t size;
} raw_data_s_type, *raw_data_p_type;
#define RAW_DATA_S_SIZE sizeof(raw_data_s_type)

typedef struct _sock_and_data_s {
	_sock_and_data_s() {}
	~_sock_and_data_s() {
	}
	raw_data_s_type raw_data;
	StreamSocket ss;
} sock_and_data_s_type, *sock_and_data_p_type;
#define SOCK_AND_DATA_S_SIZE sizeof(sock_and_data_s_type)

//const std::string EVTCPServer::SERVER_PREFIX_CFG_NAME("EVTCPServer.");
//const std::string EVTCPServer::NUM_THREADS_CFG_NAME("numThreads");
//const std::string EVTCPServer::RECV_TIME_OUT_NAME("receiveTimeOut");
//const std::string EVTCPServer::NUM_CONNECTIONS_CFG_NAME("numConnections");
//const std::string EVTCPServer::USE_IPV6_FOR_CONN("useIpv6ForConn");

// this callback is called when a submitted generic task is complete
static void file_evt_occured (EV_P_ ev_async *w, int revents)
{
	strms_pc_cb_ptr_type cb_ptr = (strms_pc_cb_ptr_type)0;
	/* for one-shot events, one must manually stop the watcher
	 * with its corresponding stop function.
	 * ev_io_stop (loop, w);
	 */
	if (!ev_is_active(w)) {
		return ;
	}

	cb_ptr = (strms_pc_cb_ptr_type)w->data;
	/* The below line of code essentially calls
	 * EVTCPServer::handleFileEvtOccured(const bool)
	 */
	((cb_ptr->objPtr)->*(cb_ptr->method))(true);

	return;
}

static void file_operation_completion(int fd, int completed_oper, void * cb_data)
{
	EVTCPServer * tcpserver = (EVTCPServer*) cb_data;
	if (tcpserver == NULL) {
		DEBUGPOINT("THIS MUST NOT HAPPEN\n");
		std::abort();
	}
	tcpserver->pushFileEvent(fd, completed_oper);
	return ;
}

static void periodic_call_for_housekeeping(EV_P_ ev_timer *w, int revents)
{
	bool ev_occurred = true;
	strms_pc_cb_ptr_type cb_ptr = (strms_pc_cb_ptr_type)0;

	if (!ev_is_active(w)) {
		return ;
	}

	cb_ptr = (strms_pc_cb_ptr_type)w->data;
	/* The below line of code essentially calls
	 * EVTCPServer::handlePeriodicWakeup(const bool&)
	 */
	if (cb_ptr) ((cb_ptr->objPtr)->*(cb_ptr->method))(ev_occurred);
	return;
}

// this callback is called when data is readable on a socket
static void data_available_on_primary_inp_fd(EV_P_ ev_io *w, int revents)
{
	bool ev_occurred = true;
	srvrs_io_cb_ptr_type cb_ptr = (srvrs_io_cb_ptr_type)0;
	/* for one-shot events, one must manually stop the watcher
	 * with its corresponding stop function.
	 * ev_io_stop (loop, w);
	 */
	if (!ev_is_active(w)) {
		debug_io_watcher(__FILE__,__LINE__,w);
		return ;
	}

	cb_ptr = (srvrs_io_cb_ptr_type)w->data;
	/* The below line of code essentially calls
	 * EVTCPServer::handleDataAvlblOnPrimaryInp(const bool)
	 */
	((cb_ptr->objPtr)->*(cb_ptr->connArrived))(ev_occurred);
	return;
}

// this callback is called when a new connection request is available
static void new_connection(EV_P_ ev_io *w, int revents)
{
	bool ev_occurred = true;
	srvrs_io_cb_ptr_type cb_ptr = (srvrs_io_cb_ptr_type)0;
	/* for one-shot events, one must manually stop the watcher
	 * with its corresponding stop function.
	 * ev_io_stop (loop, w);
	 */
	if (!ev_is_active(w)) {
		debug_io_watcher(__FILE__,__LINE__,w);
		return ;
	}

	cb_ptr = (srvrs_io_cb_ptr_type)w->data;
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
	strms_io_cb_ptr_type cb_ptr = (strms_io_cb_ptr_type)0;
	/* for one-shot events, one must manually stop the watcher
	 * with its corresponding stop function.
	 * ev_io_stop (loop, w);
	 */
	if (!ev_is_active(w)) {
		return ;
	}

	cb_ptr = (strms_io_cb_ptr_type)w->data;
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
		strms_io_cb_ptr_type cb_ptr = (strms_io_cb_ptr_type)0;
		/* for one-shot events, one must manually stop the watcher
		 * with its corresponding stop function.
		 * ev_io_stop (loop, w);
		 */
		if (!ev_is_active(w)) {
			return ;
		}

		cb_ptr = (strms_io_cb_ptr_type)w->data;
		/* The below line of code essentially calls
		 * EVTCPServer::handleAccSocketReadable(const bool) or
		 * EVTCPServer::handleCLFdReadable(const bool)
		 */
		//DEBUGPOINT("INVOKING handleAccSocketReadable\n");
		((cb_ptr->objPtr)->*(cb_ptr->dataAvailable))(*(cb_ptr->ssPtr) , true);
		// Suspending interest in events of this fd until one request is processed
		//ev_io_stop(loop, w);
		//ev_clear_pending(loop, w);
	}

	return;
}

// this callback is called when a submitted generic task is complete
static void generic_task_complete (EV_P_ ev_async *w, int revents)
{
	strms_pc_cb_ptr_type cb_ptr = (strms_pc_cb_ptr_type)0;
	/* for one-shot events, one must manually stop the watcher
	 * with its corresponding stop function.
	 * ev_io_stop (loop, w);
	 */
	if (!ev_is_active(w)) {
		return ;
	}

	cb_ptr = (strms_pc_cb_ptr_type)w->data;
	/* The below line of code essentially calls
	 * EVTCPServer::handleGenericTaskComplete(const bool)
	 */
	((cb_ptr->objPtr)->*(cb_ptr->method))(true);

	return;
}

// this callback is called when a passed domain name is resolved
static void host_addr_resolved (EV_P_ ev_async *w, int revents)
{
	strms_pc_cb_ptr_type cb_ptr = (strms_pc_cb_ptr_type)0;
	/* for one-shot events, one must manually stop the watcher
	 * with its corresponding stop function.
	 * ev_io_stop (loop, w);
	 */
	if (!ev_is_active(w)) {
		return ;
	}

	cb_ptr = (strms_pc_cb_ptr_type)w->data;
	/* The below line of code essentially calls
	 * EVTCPServer::handleHostResolved(const bool)
	 */
	((cb_ptr->objPtr)->*(cb_ptr->method))(true);

	return;
}

// this callback is called when connected socket is writable
static void async_stream_socket_cb_5 (EV_P_ ev_io *w, int revents)
{
	strms_io_cb_ptr_type cb_ptr = (strms_io_cb_ptr_type)0;
	/* for one-shot events, one must manually stop the watcher
	 * with its corresponding stop function.
	 * ev_io_stop (loop, w);
	 */
	if (!ev_is_active(w)) {
		return ;
	}

	cb_ptr = (strms_io_cb_ptr_type)w->data;
	/* The below line of code essentially calls
	 * EVTCPServer::handleConnSocketWriteable(const bool) or
	 * EVTCPServer::handleConnSocketWriteReady(const bool)
	 */
	ssize_t ret = 0;
	ret = ((cb_ptr->objPtr)->*(cb_ptr->connSocketWritable))(cb_ptr , true);

	return;
}

// this callback is called when connected socket is writable
static void async_stream_socket_cb_4 (EV_P_ ev_io *w, int revents)
{
	strms_io_cb_ptr_type cb_ptr = (strms_io_cb_ptr_type)0;
	/* for one-shot events, one must manually stop the watcher
	 * with its corresponding stop function.
	 * ev_io_stop (loop, w);
	 */
	if (!ev_is_active(w)) {
		return ;
	}

	cb_ptr = (strms_io_cb_ptr_type)w->data;
	/* The below line of code essentially calls
	 * EVTCPServer::handleConnSocketWriteable(const bool) or
	 * EVTCPServer::handleConnSocketWriteReady(const bool)
	 */
	ssize_t ret = 0;
	ret = ((cb_ptr->objPtr)->*(cb_ptr->connSocketWritable))(cb_ptr , true);

	return;
}

// this callback is called when data is readable on a connected socket
static void async_stream_socket_cb_3(EV_P_ ev_io *w, int revents)
{
	if ((revents & EV_READ) && (revents & EV_WRITE)) {
		async_stream_socket_cb_5(loop, w, revents);
	}
	else if (revents & EV_WRITE) {
		//DEBUGPOINT("HERE\n");
		async_stream_socket_cb_4(loop, w, revents);
	} 
	else if (revents & EV_READ) {
		strms_io_cb_ptr_type cb_ptr = (strms_io_cb_ptr_type)0;
		/* for one-shot events, one must manually stop the watcher
		 * with its corresponding stop function.
		 * ev_io_stop (loop, w);
		 */
		if (!ev_is_active(w)) {
			return ;
		}

		cb_ptr = (strms_io_cb_ptr_type)w->data;
		/* The below line of code essentially calls
		 * EVTCPServer::handleConnSocketReadable(const bool)
		 * EVTCPServer::handleConnSocketReadReady(const bool) or
		 */
		((cb_ptr->objPtr)->*(cb_ptr->connSocketReadable))(cb_ptr , true);
		// Suspending interest in events of this fd until one request is processed
		//ev_io_stop(loop, w);
		//ev_clear_pending(loop, w);
	}

	return;
}

/* This callback is to break all watchers and stop the loop. */
static void stop_the_loop(struct ev_loop *loop, ev_async *w, int revents)
{
	//DEBUGPOINT("Here\n");
	ev_break (loop, EVBREAK_ALL);
	return;
}

/* This callback is for completion of processing of one socket. */
/* SOMETHING HAPPENED HOUTSIDE EVENT LOOP IN ANOTHER THREAD */
static void event_notification_on_downstream_socket(struct ev_loop *loop, ev_async *w, int revents)
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

/* This callback is for processing of service requests submitted by other threads.
 * The service requests are for connecting a socket to a server,
 * sending request data to server or receiving request data from server */
/* HANDLESERVICEREQUEST submitted by abother thread. */
static void process_service_request (struct ev_loop *loop, ev_async *w, int revents)
{
	bool ev_occurred = true;
	strms_pc_cb_ptr_type cb_ptr = (strms_pc_cb_ptr_type)0;

	if (!ev_is_active(w)) {
		return ;
	}

	cb_ptr = (strms_pc_cb_ptr_type)w->data;
	/* The below line of code essentially calls
	 * EVTCPServer::handleServiceRequest(const bool)
	 */
	if (cb_ptr) ((cb_ptr->objPtr)->*(cb_ptr->method))(ev_occurred);

	return;
}

//
// EVTCPServer
//
void EVTCPServer::init()
{
	Poco::Util::AbstractConfiguration& config = appConfig();

	NUM_THREADS_CFG_NAME = ("numThreads");
	RECV_TIME_OUT_NAME = ("receiveTimeOut");
	NUM_CONNECTIONS_CFG_NAME = ("numConnections");
	USE_IPV6_FOR_CONN = ("useIpv6ForConn");
	SERVER_PREFIX_CFG_NAME = ("EVTCPServer.");

	this->_numThreads = config.getInt(SERVER_PREFIX_CFG_NAME + NUM_THREADS_CFG_NAME , 2);
	this->_receiveTimeOut = config.getInt(SERVER_PREFIX_CFG_NAME+RECV_TIME_OUT_NAME, 5);
	this->_numConnections = config.getInt(SERVER_PREFIX_CFG_NAME + NUM_CONNECTIONS_CFG_NAME , 500);
	this->_use_ipv6_for_conn = config.getBool(SERVER_PREFIX_CFG_NAME + USE_IPV6_FOR_CONN, false);
	this->_loop_active_spin_lock = create_spin_lock();
	this->_loop_active = false;
	atomic_thread_fence(std::memory_order_release);

}

void EVTCPServer::setServerPrefix(std::string serverPrefix)
{
	std::string SERVER_PREFIX_CFG_NAME = serverPrefix;
}

void EVTCPServer::setConfigNames(std::string serverPrefix, std::string numThreads, std::string receiveTimeOut,
			std::string numConnections, std::string useIpv6ForConn)
{
	SERVER_PREFIX_CFG_NAME = serverPrefix;
	NUM_THREADS_CFG_NAME = numThreads;
	RECV_TIME_OUT_NAME = receiveTimeOut;
	NUM_CONNECTIONS_CFG_NAME = numConnections;
	USE_IPV6_FOR_CONN = useIpv6ForConn;
}


EVTCPServer::EVTCPServer(EVTCPServerConnectionFactory::Ptr pFactory, Poco::UInt16 portNumber, TCPServerParams::Ptr pParams):
	_mode(EVTCPServer::SERVER_MODE),
	_socket(ServerSocket(portNumber)),
	_thread(threadName(_socket)),
	_stopped(true),
	_loop(0),
	_ssLRUList(0,0),
	_numThreads(2),
	_numConnections(500),
	//_blocking(pParams->getBlocking()),
	_blocking(false),
	_pConnectionFactory(pFactory),
	_receiveTimeOut(5),
	_sr_srl_num(0),
	_thread_pool(0),
	_stop_watcher_ptr1(0),
	_stop_watcher_ptr2(0),
	_stop_watcher_ptr3(0),
	_dns_watcher_ptr(0),
	_gen_task_compl_watcher_ptr(0),
	_file_evt_watcher_ptr(0),
	_aux_tc_queue(create_ev_queue()),
	_file_evt_queue(create_ev_queue()),
	_host_resolve_queue(create_ev_queue()),
	_use_ipv6_for_conn(false)

{
	init();
	Poco::ThreadPool& pool = Poco::ThreadPool::defaultPool(_numThreads,_numThreads);
	if (pParams) {
		int toAdd = pParams->getMaxThreads() - pool.capacity();
		if (toAdd > 0) pool.addCapacity(toAdd);
	}
	_pDispatcher = new EVTCPServerDispatcher(pFactory, pool, pParams, this);
	
}


EVTCPServer::EVTCPServer(EVTCPServerConnectionFactory::Ptr pFactory, const ServerSocket& socket, TCPServerParams::Ptr pParams):
	_mode(EVTCPServer::SERVER_MODE),
	_pipe_rd_fd(-1),
	_pipe_wr_fd(-1),
	_socket(socket),
	_thread(threadName(socket)),
	_stopped(true),
	_loop(0),
	_ssLRUList(0,0),
	_numThreads(2),
	_numConnections(500),
	//_blocking(pParams->getBlocking()),
	_blocking(false),
	_pConnectionFactory(pFactory),
	_receiveTimeOut(5),
	_sr_srl_num(0),
	_thread_pool(0),
	_stop_watcher_ptr1(0),
	_stop_watcher_ptr2(0),
	_stop_watcher_ptr3(0),
	_dns_watcher_ptr(0),
	_gen_task_compl_watcher_ptr(0),
	_file_evt_watcher_ptr(0),
	_aux_tc_queue(create_ev_queue()),
	_file_evt_queue(create_ev_queue()),
	_host_resolve_queue(create_ev_queue()),
	_use_ipv6_for_conn(false)

{
	init();
	Poco::ThreadPool& pool = Poco::ThreadPool::defaultPool(_numThreads,_numThreads);
	if (pParams) {
		int toAdd = pParams->getMaxThreads() - pool.capacity();
		if (toAdd > 0) pool.addCapacity(toAdd);
	}
	_pDispatcher = new EVTCPServerDispatcher(pFactory, pool, pParams, this);
}


EVTCPServer::EVTCPServer(EVTCPServerConnectionFactory::Ptr pFactory, Poco::ThreadPool& threadPool, const ServerSocket& socket, TCPServerParams::Ptr pParams):
	_mode(EVTCPServer::SERVER_MODE),
	_pipe_rd_fd(-1),
	_pipe_wr_fd(-1),
	_socket(socket),
	_thread(threadName(socket)),
	_stopped(true),
	_loop(0),
	_ssLRUList(0,0),
	_numThreads(2),
	_numConnections(500),
	//_blocking(pParams->getBlocking()),
	_blocking(false),
	_pConnectionFactory(pFactory),
	_receiveTimeOut(5),
	_sr_srl_num(0),
	_thread_pool(0),
	_stop_watcher_ptr1(0),
	_stop_watcher_ptr2(0),
	_stop_watcher_ptr3(0),
	_dns_watcher_ptr(0),
	_gen_task_compl_watcher_ptr(0),
	_file_evt_watcher_ptr(0),
	_aux_tc_queue(create_ev_queue()),
	_file_evt_queue(create_ev_queue()),
	_host_resolve_queue(create_ev_queue()),
	_use_ipv6_for_conn(false)

{
	init();
	_pDispatcher = new EVTCPServerDispatcher(pFactory, threadPool, pParams, this);
}

EVTCPServer::EVTCPServer(EVTCPServerConnectionFactory::Ptr pFactory, int pipe_rd_fd, int pipe_wr_fd, TCPServerParams::Ptr pParams):
	_mode(EVTCPServer::COMMAND_LINE_MODE),
	_pipe_rd_fd(pipe_rd_fd),
	_pipe_wr_fd(pipe_wr_fd),
	_thread(threadName(_pipe_rd_fd)),
	_stopped(true),
	_loop(0),
	_ssLRUList(0,0),
	_numThreads(2),
	_numConnections(500),
	//_blocking(pParams->getBlocking()),
	_blocking(false),
	_pConnectionFactory(pFactory),
	_receiveTimeOut(5),
	_sr_srl_num(0),
	_thread_pool(0),
	_stop_watcher_ptr1(0),
	_stop_watcher_ptr2(0),
	_stop_watcher_ptr3(0),
	_dns_watcher_ptr(0),
	_gen_task_compl_watcher_ptr(0),
	_file_evt_watcher_ptr(0),
	_aux_tc_queue(create_ev_queue()),
	_file_evt_queue(create_ev_queue()),
	_host_resolve_queue(create_ev_queue()),
	_use_ipv6_for_conn(false)

{
	init();
	Poco::ThreadPool& pool = Poco::ThreadPool::defaultPool(_numThreads,_numThreads);
	if (pParams) {
		int toAdd = pParams->getMaxThreads() - pool.capacity();
		if (toAdd > 0) pool.addCapacity(toAdd);
	}
	_pDispatcher = new EVTCPServerDispatcher(pFactory, pool, pParams, this);
	
}

EVTCPServer::~EVTCPServer()
{
	try {
		stop();
		_pDispatcher->release();
		freeClear();
	}
	catch (...) {
		poco_unexpected();
	}
}

void EVTCPServer::freeClear()
{
    for ( ASColMapType::iterator it = _accssColl.begin(); it != _accssColl.end(); ++it ) {
        delete it->second;
    }
    _accssColl.clear();

	ef_unset_cb_func();
	for (FileEvtSubscrMap::iterator it = _file_evt_subscriptions.begin(); it != _file_evt_subscriptions.end(); ++it) {
		delete it->second._usN;
	}
	destroy_spin_lock(_loop_active_spin_lock);
}

void EVTCPServer::clearAcceptedSocket(poco_socket_t fd)
{
	//DEBUGPOINT("CLEARING FOR [%d]\n", fd);
	EVAcceptedStreamSocket *tn = getTn(fd);
	_accssColl.erase(fd);
	_ssLRUList.remove(tn);
	{
		ev_io * socket_watcher_ptr = 0;
		socket_watcher_ptr = tn->getSocketWatcher();
		if (socket_watcher_ptr && ev_is_active(socket_watcher_ptr)) {
			ev_io_stop(this->_loop, socket_watcher_ptr);
			ev_clear_pending(this->_loop, socket_watcher_ptr);
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
		{

			ev_spin_lock(this->_loop_active_spin_lock);
			/* Calls stop_the_loop */
			ev_async_send(this->_loop, this->_stop_watcher_ptr1);

			_loop_active = false;
			atomic_thread_fence(std::memory_order_release);

			ev_spin_unlock(this->_loop_active_spin_lock);

		}

		_thread.join();
		_pDispatcher->stop();
		destroy_thread_pool(this->_thread_pool);
	}
}

ssize_t EVTCPServer::sendData(StreamSocket& ss, void * chptr, size_t size, int *wait_mode_ptr)
{
	ssize_t ret = 0;
	errno = 0;
	try {
		//ret = ss.sendBytes(chptr, size , 0);
		//DEBUGPOINT("sockfd = [%d]\n", ss.impl()->sockfd());
		//DEBUGPOINT("&ss = [%p]\n", &ss);
		//DEBUGPOINT("size = [%zu]\n", size);
		//DEBUGPOINT("chptr = [%s]\n", (char*)chptr);
		ret = ss.sendBytes(chptr, size );
		if (ret < 0 && wait_mode_ptr) *wait_mode_ptr = ret;
		else if (wait_mode_ptr) *wait_mode_ptr = 0;
		if (wait_mode_ptr) {
			if ((ret < 0) && !(ss.impl()->secure()))
				*wait_mode_ptr = -2;
		}
	}
	catch (...) {
		if (ret < 0 && wait_mode_ptr) *wait_mode_ptr = ret;
		else if (wait_mode_ptr) *wait_mode_ptr = 0;
		if (wait_mode_ptr) {
			if ((ret < 0) && !(ss.impl()->secure()))
				*wait_mode_ptr = -2;
		}
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
			}
			return -1;
		}
	}
	return ret;
}

ssize_t EVTCPServer::sendData(int fd, void * chptr, size_t size, int * wait_mode_ptr)
{
	ssize_t ret = 0;
	errno = 0;
	ret = send(fd, chptr, size , 0);
	if (ret < 0 && wait_mode_ptr) *wait_mode_ptr = ret;
	else if (wait_mode_ptr) *wait_mode_ptr = 0;
	if (wait_mode_ptr) {
		if (ret < 0)
			*wait_mode_ptr = -2;
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
			}
			return -1;
		}
	}
	return ret;
}

ssize_t EVTCPServer::handleConnSocketConnected(strms_io_cb_ptr_type cb_ptr, const bool& ev_occured)
{
	int optval = 0;
	unsigned int optlen = sizeof(optval);
	EVConnectedStreamSocket * cn = cb_ptr->cn;

	cn->setState(EVConnectedStreamSocket::NOT_WAITING);
	ev_io_stop(this->_loop, cn->getSocketWatcher());
	ev_clear_pending(this->_loop, cn->getSocketWatcher());

	EVAcceptedStreamSocket *tn = getTn(cn->getAccSockfd());
	//tn->decrNumCSEvents();

	//DEBUGPOINT("CONNECTED [%d]\n", cn->getStreamSocket().impl()->sockfd());
	getsockopt(cn->getStreamSocket().impl()->sockfd(), SOL_SOCKET, SO_ERROR, (void*)&optval, &optlen);
	/* Enqueue the notification only if the accepted socket is still being processed.
	 * */
	if ((tn->getProcState()) && tn->srInSession(cb_ptr->sr_num)) {
		if (!optval) {
			cn->getStreamSocket().impl()->setBlocking(_blocking);
			fcntl(cn->getStreamSocket().impl()->sockfd(), F_SETFL, O_NONBLOCK);
		}
		EVEventNotification * usN = 0;
		usN = new EVEventNotification(cb_ptr->sr_num, (cn->getStreamSocket().impl()->sockfd()), 
												cb_ptr->cb_evid_num,
												(!optval)?1:-1,
												optval);
		usN->setRecvStream(cn->getRcvMemStream());
		usN->setSendStream(cn->getSendMemStream());
		enqueue(tn->getIoEventQueue(), (void*)usN);
		tn->newdecrNumCSEvents();
		if (!(tn->sockBusy())) {
			srCompleteEnqueue(tn);
		}
		else {
			tn->setWaitingTobeEnqueued(true);
		}
	}
	else {
		DEBUGPOINT("IS THIS AN IMPOSSIBLE CONDITION for %d\n", tn->getSockfd());
		std::abort();
	}

	return 1;
}

ssize_t EVTCPServer::handleConnSocketWriteable(strms_io_cb_ptr_type cb_ptr, const bool& ev_occured)
{
	ssize_t ret = 0;
	EVConnectedStreamSocket * cn = cb_ptr->cn;
	cn->setTimeOfLastUse();
	if (cn->getState() == EVConnectedStreamSocket::BEFORE_CONNECT) {
		//DEBUGPOINT("HERE BC\n");
		cn->setState(EVConnectedStreamSocket::NOT_WAITING);
		return handleConnSocketConnected(cb_ptr, ev_occured);
	}

	//EVAcceptedStreamSocket *tn = _accssColl[cn->getAccSockfd()];
	if (!cn->sendDataAvlbl()) {
		goto handleConnSocketWritable_finally;
	}

	{
		chunked_memory_stream * cms = 0;

		ssize_t ret1 = 0;
		int count = 0;

		cms = cn->getSendMemStream();
		void * nodeptr = 0;
		void * buffer = 0;
		size_t bytes = 0;
		nodeptr = cms->get_next(0);
		while (nodeptr) {
			count ++;
			buffer = cms->get_buffer(nodeptr);
			bytes = cms->get_buffer_len(nodeptr);

			//ret1 = sendData(streamSocket.impl()->sockfd(), buffer, bytes);
			//DEBUGPOINT("SENDING_DATA ON CONN SOCK %d\n", cn->getStreamSocket().impl()->sockfd());
			ret1 = sendData(cn->getStreamSocket(), buffer, bytes);
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

handleConnSocketWritable_finally:
	if (ret >=0) {
		/* If there is more data to be sent, wait for 
		 * the socket to become writable again.
		 * */
		if (!cn->sendDataAvlbl()) ret = 1;
		else ret = 0;
	}

	if (ret > 0) {
		ev_io * socket_watcher_ptr = 0;
		strms_io_cb_ptr_type cb_ptr = 0;

		socket_watcher_ptr = cn->getSocketWatcher();

		if (cn->getState() == EVConnectedStreamSocket::WAITING_FOR_WRITE) {
			ev_io_stop(this->_loop, socket_watcher_ptr);
			ev_clear_pending(this->_loop, socket_watcher_ptr);
			cn->setState(EVConnectedStreamSocket::NOT_WAITING);
		}
		else if (cn->getState() == EVConnectedStreamSocket::WAITING_FOR_READWRITE) {
			ev_io_stop(this->_loop, socket_watcher_ptr);
			ev_clear_pending(this->_loop, socket_watcher_ptr);
			ev_io_init (socket_watcher_ptr, async_stream_socket_cb_3, cn->getStreamSocket().impl()->sockfd(), EV_READ);
			ev_io_start (this->_loop, socket_watcher_ptr);
			cn->setState(EVConnectedStreamSocket::WAITING_FOR_READ);
		}
		else {
			/* It should not come here otherwise. */
			DEBUGPOINT("It should not come here otherwise.[%d]\n", cn->getState());
			std::abort();
		}

		// TBD Handle dispatching of EVENT here. TBD

		/* For the case of sending data, calling the upstream event back is not done
		 * A send simply tries to transfer data to the socket
		 *
		 * If there is any failure the caller is expected to find from the 
		 * receive side.
		 * */
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
		cn->setSockInError();

		// TBD Handle dispatching of EVENT here. TBD

		/* For the case of sending data, calling the upstream event back is not done
		 * A send simply tries to transfer data to the socket
		 *
		 * If there is any failure the caller is expected to find from the 
		 * receive side.
		 * */
	}

	if (ret != 0) {
		//srComplete(tn);
		//tn->decrNumCSEvents();
	}

	return ret;
}

ssize_t EVTCPServer::handleCLWrFdWritable(StreamSocket & streamSocket, const bool& ev_occured)
{
	ssize_t ret = 0;
	EVAcceptedStreamSocket *tn = getTn(streamSocket.impl()->sockfd());
	if (!tn) return -1;
	tn->setTimeOfLastUse();
	_ssLRUList.move(tn);
	if (!tn->resDataAvlbl()) {
		goto handleCLWrFdWritable_finally;
	}

	{
		chunked_memory_stream * cms = 0;

		ssize_t ret1 = 0;
		int count = 0;

		cms = tn->getResMemStream();
		void * nodeptr = 0;
		void * buffer = 0;
		size_t bytes = 0;
		nodeptr = cms->get_next(0);
		//DEBUGPOINT("Here np = %p for %d\n", nodeptr, tn->getSockfd());
		while (nodeptr) {
			count ++;
			buffer = cms->get_buffer(nodeptr);
			bytes = cms->get_buffer_len(nodeptr);

			//ret1 = sendData(streamSocket.impl()->sockfd(), buffer, bytes);
			//DEBUGPOINT("SENDING_DATA ON ACCP SOCK %d\n", streamSocket.impl()->sockfd());
			ret1 = writeData(tn->getOutStreamSocket().impl()->sockfd(), buffer, bytes);
			if (ret1 > 0) {
				cms->erase(ret1);
				nodeptr = cms->get_next(0);
				buffer = 0;
				bytes = 0;
				ret += ret1;
				ret1 = 0;
				//DEBUGPOINT("Here for [%zd] %d [%s]\n", ret, tn->getSockfd(), strerror(errno));
			}
			else if (ret1 == 0) {
				// Add to waiting for being write ready.
				//DEBUGPOINT("Here for [%zd] %d [%s]\n", ret, tn->getSockfd(), strerror(errno));
				ret = 0;
				break;
			}
			else {
				//DEBUGPOINT("Here for [%zd] %d [%s]\n", ret, tn->getSockfd(), strerror(errno));
				ret = -1;
				break;
			}
		}
	}

handleCLWrFdWritable_finally:
	if (ret >=0) {
		/* If there is more data to be sent, wait for 
		 * the socket to become writable again.
		 * */
		if (!tn->resDataAvlbl()) ret = 1;
		else ret = 0;
	}
	//DEBUGPOINT("Here ret = %zd state = %d for %d\n", ret, tn->getState(), tn->getSockfd());

	if (ret > 0) {
		ev_io * socket_watcher_ptr = 0;
		strms_io_cb_ptr_type cb_ptr = 0;

		socket_watcher_ptr = tn->getSocketWatcher();

		if (tn->getState() == EVAcceptedStreamSocket::WAITING_FOR_WRITE) {
			ev_io_stop(this->_loop, socket_watcher_ptr);
			ev_clear_pending(this->_loop, socket_watcher_ptr);
			tn->setState(EVAcceptedStreamSocket::NOT_WAITING);
		}
		else if (tn->getState() == EVAcceptedStreamSocket::WAITING_FOR_READWRITE) {
			ev_io_stop(this->_loop, socket_watcher_ptr);
			ev_clear_pending(this->_loop, socket_watcher_ptr);
			ev_io_init (socket_watcher_ptr, async_stream_socket_cb_1, streamSocket.impl()->sockfd(), EV_READ);
			ev_io_start (this->_loop, socket_watcher_ptr);
			tn->setState(EVAcceptedStreamSocket::WAITING_FOR_READ);
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
		//DEBUGPOINT("Here for %d\n", tn->getSockfd());
		tn->setSockInError();
	}

	return ret;
}

ssize_t EVTCPServer::handleAccSocketWritable(StreamSocket & streamSocket, const bool& ev_occured)
{
	ssize_t ret = 0;
	EVAcceptedStreamSocket *tn = getTn(streamSocket.impl()->sockfd());
	if (!tn) return -1;
	tn->setTimeOfLastUse();
	_ssLRUList.move(tn);
	if (!tn->resDataAvlbl()) {
		goto handleAccSocketWritable_finally;
	}

	{
		chunked_memory_stream * cms = 0;

		ssize_t ret1 = 0;
		int count = 0;

		cms = tn->getResMemStream();
		void * nodeptr = 0;
		void * buffer = 0;
		size_t bytes = 0;
		nodeptr = cms->get_next(0);
		//DEBUGPOINT("Here np = %p for %d\n", nodeptr, tn->getSockfd());
		while (nodeptr) {
			count ++;
			buffer = cms->get_buffer(nodeptr);
			bytes = cms->get_buffer_len(nodeptr);

			//ret1 = sendData(streamSocket.impl()->sockfd(), buffer, bytes);
			//DEBUGPOINT("SENDING_DATA ON ACCP SOCK %d\n", streamSocket.impl()->sockfd());
			ret1 = sendData(streamSocket, buffer, bytes);
			if (ret1 > 0) {
				cms->erase(ret1);
				nodeptr = cms->get_next(0);
				buffer = 0;
				bytes = 0;
				ret += ret1;
				ret1 = 0;
				//DEBUGPOINT("Here for [%zd] %d [%s]\n", ret, tn->getSockfd(), strerror(errno));
			}
			else if (ret1 == 0) {
				// Add to waiting for being write ready.
				//DEBUGPOINT("Here for [%zd] %d [%s]\n", ret, tn->getSockfd(), strerror(errno));
				ret = 0;
				break;
			}
			else {
				//DEBUGPOINT("Here for [%zd] %d [%s]\n", ret, tn->getSockfd(), strerror(errno));
				ret = -1;
				break;
			}
		}
	}

handleAccSocketWritable_finally:
	if (ret >=0) {
		/* If there is more data to be sent, wait for 
		 * the socket to become writable again.
		 * */
		if (!tn->resDataAvlbl()) ret = 1;
		else ret = 0;
	}
	//DEBUGPOINT("Here ret = %zd state = %d for %d\n", ret, tn->getState(), tn->getSockfd());

	if (ret > 0) {
		ev_io * socket_watcher_ptr = 0;
		strms_io_cb_ptr_type cb_ptr = 0;

		socket_watcher_ptr = tn->getSocketWatcher();

		if (tn->getState() == EVAcceptedStreamSocket::WAITING_FOR_WRITE) {
			ev_io_stop(this->_loop, socket_watcher_ptr);
			ev_clear_pending(this->_loop, socket_watcher_ptr);
			tn->setState(EVAcceptedStreamSocket::NOT_WAITING);
		}
		else if (tn->getState() == EVAcceptedStreamSocket::WAITING_FOR_READWRITE) {
			ev_io_stop(this->_loop, socket_watcher_ptr);
			ev_clear_pending(this->_loop, socket_watcher_ptr);
			ev_io_init (socket_watcher_ptr, async_stream_socket_cb_1, streamSocket.impl()->sockfd(), EV_READ);
			ev_io_start (this->_loop, socket_watcher_ptr);
			tn->setState(EVAcceptedStreamSocket::WAITING_FOR_READ);
		}
		else {
			/* It should not come here otherwise. */
			std::abort();
		}
		/* Switching should take place after the data is
		 * completely sent to the client.
		 */
		if (!tn->resDataAvlbl() && tn->getSockUpgradeTo()) {
			/*
			 * HTTP2 enhancement
			 * Get socket fd out
			 * Clear tn
			 * Create a different kind of acc socket
			 * which continuously reads data and
			 * handles on data available differently.
			 */
			if (tn->getSockUpgradeTo() == EVAcceptedStreamSocket::WEBSOCKET) {
				switch (tn->getSockMode()) {
					case EVAcceptedStreamSocket::SERVER_MODE:
						switch (tn->getSockUpgradeTo()) {
							case EVAcceptedStreamSocket::WEBSOCKET:
								tn->getStreamSocketPtr()->impl()->managed(true);
								tn->setSockMode(EVAcceptedStreamSocket::WEBSOCKET_MODE);
								monitorDataOnAccSocket(tn);
								break;
							case EVAcceptedStreamSocket::HTTP2:
								DEBUGPOINT("HTTP2 not implemented\n");
								std::abort();
								break;
							case EVAcceptedStreamSocket::NONE:
								break;
							default:
								DEBUGPOINT("Invalid upgrade to [%d]\n", tn->getSockUpgradeTo());
								std::abort();

						}
						break;
					default:
						break;

				}
			}
			else if (tn->getSockUpgradeTo() == EVAcceptedStreamSocket::HTTP2) {
				DEBUGPOINT("HTTP2 not yet implemented\n");
				std::abort();
			}
			else {
				DEBUGPOINT("Protocol not supported\n");
				std::abort();
			}
		}
		else {
		}
		if (tn->shutdownInitiated()) {
			//DEBUGPOINT("SHUTTING DOWN HERE\n");
			if (!tn->sockBusy() && !tn->newpendingCSEvents()) {
				clearAcceptedSocket(tn->getSockfd());
			}
			else {
				tn->setSockInError();
			}
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
		//DEBUGPOINT("Here for %d\n", tn->getSockfd());
		tn->setSockInError();
		if (tn->shutdownInitiated() && !tn->sockBusy() && !tn->newpendingCSEvents()) {
			//DEBUGPOINT("SHUTTING DOWN HERE\n");
			clearAcceptedSocket(tn->getSockfd());
		}
	}

	return ret;
}

ssize_t EVTCPServer::receiveData(StreamSocket & ss, void * chptr, size_t size, int * wait_mode_ptr)
{
	ssize_t ret = 0;
	errno = 0;

	try {
		ret = ss.receiveBytes(chptr, size );
	}
	catch (std::exception & e) {
	}
	if (ret < 0 && wait_mode_ptr) *wait_mode_ptr = ret;
	else if (wait_mode_ptr) *wait_mode_ptr = 0;
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

ssize_t EVTCPServer::writeData(int fd, void * chptr, size_t size, int * wait_mode_ptr)
{
	ssize_t ret = 0;
	errno = 0;
	//DEBUGPOINT("fd = [%d]\n", fd);
	ret = write(fd, chptr, size);
	if (ret < 0 && wait_mode_ptr) *wait_mode_ptr = ret;
	else if (wait_mode_ptr) *wait_mode_ptr = 0;
	if (wait_mode_ptr) {
		if (ret < 0)
			*wait_mode_ptr = -2;
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
			}
			return -1;
		}
	}
	return ret;
}

ssize_t EVTCPServer::readData(int fd, void * chptr, size_t size, int * wait_mode_ptr)
{
	ssize_t ret = 0;
	errno = 0;
	ret = read(fd, chptr, size);
	if (ret < 0 && wait_mode_ptr) *wait_mode_ptr = ret;
	else if (wait_mode_ptr) *wait_mode_ptr = 0;
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
			DEBUGPOINT("%d:%d-%s\n", errno, fd, error_string);
			return -1;
		}
	}
	return ret;
}

ssize_t EVTCPServer::receiveData(int fd, void * chptr, size_t size, int * wait_mode_ptr)
{
	ssize_t ret = 0;
	errno = 0;
	ret = recv(fd, chptr, size , 0);
	if (ret < 0 && wait_mode_ptr) *wait_mode_ptr = ret;
	else if (wait_mode_ptr) *wait_mode_ptr = 0;
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
			DEBUGPOINT("%d:%d-%s\n", errno, fd, error_string);
			return -1;
		}
	}
	return ret;
}

ssize_t EVTCPServer::handleConnSocketReadAndWriteReady(strms_io_cb_ptr_type cb_ptr, const bool& ev_occured)
{
	//DEBUGPOINT("EVTCPServer::handleConnSocketReadAndWriteReady\n");
	ssize_t ret = 0;
	size_t received_bytes = 0;
	EVConnectedStreamSocket *cn = cb_ptr->cn;
	cn->setTimeOfLastUse();
	errno = 0;

	EVAcceptedStreamSocket *tn = getTn(cn->getAccSockfd());
	if (!tn) {
		DEBUGPOINT("THIS CONDITION MUST NEVER HAPPEN\n");
		std::abort();
		return -1;
	}
	EVConnectedStreamSocket *ref_cn = tn->getProcState()->getEVConnSock(cn->getSockfd());
	if ((!ref_cn) || (ref_cn->getSockfd() != cn->getSockfd())) {
		DEBUGPOINT("THIS CONDITION MUST NEVER HAPPEN\n");
		std::abort();
		return -1;
	}

	//DEBUGPOINT("EVTCPServer::handleConnSocketReadAndWriteReady\n");
	EVEventNotification * usN = 0;
	if ((tn->getProcState()) && tn->srInSession(cb_ptr->sr_num)) {
		usN = new EVEventNotification(cb_ptr->sr_num, (cn->getStreamSocket().impl()->sockfd()), 
												cb_ptr->cb_evid_num,
												(ret)?ret:1, 0);
		usN->setConnSockState(EVEventNotification::READY_FOR_READWRITE);
		enqueue(tn->getIoEventQueue(), (void*)usN);
		tn->newdecrNumCSEvents();
		if (!(tn->sockBusy())) {
			srCompleteEnqueue(tn);
		}
		else {
			tn->setWaitingTobeEnqueued(true);
		}
	}
	else {
		DEBUGPOINT("IS THIS AN IMPOSSIBLE CONDITION for %d\n", tn->getSockfd());
		std::abort();
	}
	ev_io * socket_watcher_ptr = cn->getSocketWatcher();
	ev_io_stop(this->_loop, socket_watcher_ptr);
	ev_clear_pending(this->_loop, socket_watcher_ptr);
	cn->setState(EVConnectedStreamSocket::NOT_WAITING);
	DEBUGPOINT("EVTCPServer::handleConnSocketReadAndWriteReady %d\n", cb_ptr->connSocketManaged);

	if (cb_ptr->connSocketManaged) {
		ref_cn->invalidateSocket();
		tn->getProcState()->eraseEVConnSock(cn->getSockfd());
	}
	return ret;
}

ssize_t EVTCPServer::handleConnSocketWriteReady(strms_io_cb_ptr_type cb_ptr, const bool& ev_occured)
{
	//DEBUGPOINT("EVTCPServer::handleConnSocketWriteReady\n");
	ssize_t ret = 0;
	size_t received_bytes = 0;
	EVConnectedStreamSocket *cn = cb_ptr->cn;
	cn->setTimeOfLastUse();
	errno = 0;

	EVAcceptedStreamSocket *tn = getTn(cn->getAccSockfd());
	if (!tn) {
		DEBUGPOINT("THIS CONDITION MUST NEVER HAPPEN\n");
		std::abort();
		return -1;
	}
	EVConnectedStreamSocket *ref_cn = tn->getProcState()->getEVConnSock(cn->getSockfd());
	if ((!ref_cn) || (ref_cn->getSockfd() != cn->getSockfd())) {
		DEBUGPOINT("THIS CONDITION MUST NEVER HAPPEN\n");
		std::abort();
		return -1;
	}

	//DEBUGPOINT("EVTCPServer::handleConnSocketWriteReady\n");
	EVEventNotification * usN = 0;
	if ((tn->getProcState()) && tn->srInSession(cb_ptr->sr_num)) {
		usN = new EVEventNotification(cb_ptr->sr_num, (cn->getStreamSocket().impl()->sockfd()), 
												cb_ptr->cb_evid_num,
												(ret)?ret:1, 0);
		usN->setConnSockState(EVEventNotification::READY_FOR_WRITE);
		enqueue(tn->getIoEventQueue(), (void*)usN);
		tn->newdecrNumCSEvents();
		if (!(tn->sockBusy())) {
			srCompleteEnqueue(tn);
		}
		else {
			tn->setWaitingTobeEnqueued(true);
		}
	}
	else {
		DEBUGPOINT("IS THIS AN IMPOSSIBLE CONDITION for %d\n", tn->getSockfd());
		std::abort();
	}
	ev_io * socket_watcher_ptr = cn->getSocketWatcher();
	ev_io_stop(this->_loop, socket_watcher_ptr);
	ev_clear_pending(this->_loop, socket_watcher_ptr);
	cn->setState(EVConnectedStreamSocket::NOT_WAITING);
	//DEBUGPOINT("EVTCPServer::handleConnSocketWriteReady\n");

	//DEBUGPOINT("EVTCPServer::handleConnSocketWriteReady %d\n", cb_ptr->connSocketManaged);
	if (cb_ptr->connSocketManaged) {
		ref_cn->invalidateSocket();
		tn->getProcState()->eraseEVConnSock(cn->getSockfd());
	}
	return ret;
}

ssize_t EVTCPServer::handleConnSocketReadReady(strms_io_cb_ptr_type cb_ptr, const bool& ev_occured)
{
	//DEBUGPOINT("EVTCPServer::handleConnSocketReadReady\n");
	ssize_t ret = 0;
	size_t received_bytes = 0;
	EVConnectedStreamSocket *cn = cb_ptr->cn;
	cn->setTimeOfLastUse();
	errno = 0;

	//DEBUGPOINT("EVTCPServer::handleConnSocketReadReady\n");
	EVAcceptedStreamSocket *tn = getTn(cn->getAccSockfd());
	if (!tn) {
		DEBUGPOINT("THIS CONDITION MUST NEVER HAPPEN\n");
		std::abort();
		return -1;
	}
	EVConnectedStreamSocket *ref_cn = tn->getProcState()->getEVConnSock(cn->getSockfd());
	if ((!ref_cn) || (ref_cn->getSockfd() != cn->getSockfd())) {
		DEBUGPOINT("THIS CONDITION MUST NEVER HAPPEN\n");
		std::abort();
		return -1;
	}

	EVEventNotification * usN = 0;
	if ((tn->getProcState()) && tn->srInSession(cb_ptr->sr_num)) {
		usN = new EVEventNotification(cb_ptr->sr_num, (cn->getStreamSocket().impl()->sockfd()), 
												cb_ptr->cb_evid_num,
												(ret)?ret:1, 0);
		usN->setConnSockState(EVEventNotification::READY_FOR_READ);
		enqueue(tn->getIoEventQueue(), (void*)usN);
		tn->newdecrNumCSEvents();
		if (!(tn->sockBusy())) {
			srCompleteEnqueue(tn);
		}
		else {
			tn->setWaitingTobeEnqueued(true);
		}
	}
	else {
		DEBUGPOINT("IS THIS AN IMPOSSIBLE CONDITION for %d\n", tn->getSockfd());
		std::abort();
	}
	ev_io * socket_watcher_ptr = cn->getSocketWatcher();
	ev_io_stop(this->_loop, socket_watcher_ptr);
	ev_clear_pending(this->_loop, socket_watcher_ptr);
	cn->setState(EVConnectedStreamSocket::NOT_WAITING);
	//DEBUGPOINT("EVTCPServer::handleConnSocketReadReady\n");

	if (cb_ptr->connSocketManaged) {
		ref_cn->invalidateSocket();
		tn->getProcState()->eraseEVConnSock(cn->getSockfd());
	}
	return ret;
}

ssize_t EVTCPServer::handleConnSocketReadable(strms_io_cb_ptr_type cb_ptr, const bool& ev_occured)
{
	ssize_t ret = 0;
	size_t received_bytes = 0;
	EVConnectedStreamSocket *cn = cb_ptr->cn;
	cn->setTimeOfLastUse();
	if (cn->getState() == EVConnectedStreamSocket::BEFORE_CONNECT) {
		DEBUGPOINT("HERE BC\n");
		cn->setState(EVConnectedStreamSocket::NOT_WAITING);
		return handleConnSocketConnected(cb_ptr, ev_occured);
	}
	errno = 0;

	EVAcceptedStreamSocket *tn = getTn(cn->getAccSockfd());
	if (!tn) {
		DEBUGPOINT("THIS CONDITION MUST NEVER HAPPEN\n");
		std::abort();
		return -1;
	}
	EVConnectedStreamSocket *ref_cn = tn->getProcState()->getEVConnSock(cn->getSockfd());
	if ((!ref_cn) || (ref_cn->getSockfd() != cn->getSockfd())) {
		DEBUGPOINT("THIS CONDITION MUST NEVER HAPPEN\n");
		std::abort();
		return -1;
	}
	{
		ssize_t ret1 = 0;
		int count = 0;
		do {
			count ++;
			void * buffer = malloc(TCP_BUFFER_SIZE);
			memset(buffer,0,TCP_BUFFER_SIZE);
			//ret1 = receiveData(streamSocket.impl()->sockfd(), buffer, TCP_BUFFER_SIZE);
			ret1 = receiveData(cn->getStreamSocket(), buffer, TCP_BUFFER_SIZE);
			if (ret1 >0) {
				//printf("%zd\n", ret1);
				cn->pushRcvData(buffer, (size_t)ret1);
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

handleConnSocketReadable_finally:
	/* ret will be 0 after recv even on a tickled socket
	 * in case of SSL handshake.
	 * */
	//DEBUGPOINT("Return value of read = %zd\n", ret);
	if (ret != 0) {
		ev_io * socket_watcher_ptr = 0;
		socket_watcher_ptr = cn->getSocketWatcher();
		if (cn->getState() == EVConnectedStreamSocket::WAITING_FOR_READ) {
			ev_io_stop(this->_loop, socket_watcher_ptr);
			ev_clear_pending(this->_loop, socket_watcher_ptr);
			cn->setState(EVConnectedStreamSocket::NOT_WAITING);
		}
		else if (cn->getState() == EVConnectedStreamSocket::WAITING_FOR_READWRITE) {
			ev_io_stop(this->_loop, socket_watcher_ptr);
			ev_clear_pending(this->_loop, socket_watcher_ptr);
			ev_io_init (socket_watcher_ptr, async_stream_socket_cb_3, cn->getSockfd(), EV_WRITE);
			ev_io_start (this->_loop, socket_watcher_ptr);
			cn->setState(EVConnectedStreamSocket::WAITING_FOR_WRITE);
		}
		else {
			/* It should not come here otherwise. */
			DEBUGPOINT("SHOULD NOT HAVE REACHED HERE %d\n", cn->getState());
			std::abort();
		}
		//tn->decrNumCSEvents();

	}

	if ((ret >=0) && cn->rcvDataAvlbl()) {
		EVEventNotification * usN = 0;
		if ((tn->getProcState()) && tn->srInSession(cb_ptr->sr_num)) {
			usN = new EVEventNotification(cb_ptr->sr_num, (cn->getStreamSocket().impl()->sockfd()), 
													cb_ptr->cb_evid_num,
													(ret)?ret:1, 0);
			usN->setRecvStream(cn->getRcvMemStream());
			usN->setSendStream(cn->getSendMemStream());
			enqueue(tn->getIoEventQueue(), (void*)usN);
			tn->newdecrNumCSEvents();
			if (!(tn->sockBusy())) {
				srCompleteEnqueue(tn);
			}
			else {
				tn->setWaitingTobeEnqueued(true);
			}
		}
		else {
			DEBUGPOINT("IS THIS AN IMPOSSIBLE CONDITION for %d\n", tn->getSockfd());
			std::abort();
		}
	}
	else if (ret<0) {
		cn->setSockInError();
		EVEventNotification * usN = 0;
		if ((tn->getProcState()) && tn->srInSession(cb_ptr->sr_num)) {
			usN = new EVEventNotification(cb_ptr->sr_num, (cn->getStreamSocket().impl()->sockfd()), 
													cb_ptr->cb_evid_num,
													-1, errno);
			enqueue(tn->getIoEventQueue(), (void*)usN);
			tn->newdecrNumCSEvents();
			if (!(tn->sockBusy())) {
				cn->setSockInError();
				srCompleteEnqueue(tn);
			}
			else {
				tn->setWaitingTobeEnqueued(true);
			}
		}
		else {
			DEBUGPOINT("IS THIS AN IMPOSSIBLE CONDITION for %d\n", tn->getSockfd());
			std::abort();
		}
	}
	else {
	}

	return ret;
}

ssize_t EVTCPServer::handleAccWebSocketReadable(StreamSocket & ss, const bool& ev_occured)
{
	ssize_t ret = 0;
	size_t received_bytes = 0;
	EVAcceptedStreamSocket *tn = getTn(ss.impl()->sockfd());

	char buffer[128];
	memset(buffer,0,128);

	try {
		ret = ss.receiveBytes(buffer, 127, MSG_PEEK);
		//ret = recv(ss.impl()->sockfd(), buffer, 1, MSG_PEEK);
		//ret = recv(ss.impl()->sockfd(), buffer, 1, 0);
		//DEBUGPOINT("Here ret = [%zd] errno = [%d]\n", ret, errno);
		//DEBUGPOINT("MSG = [%s]\n", buffer+14);
		if (ret > 0) {

			{
				tn->setProcState(_pConnectionFactory->createReqProcState(this));
				tn->getProcState()->setMode(EVAcceptedStreamSocket::WEBSOCKET_MODE);
				//DEBUGPOINT("Created processing state %p for %d\n", tn->getProcState(), tn->getSockfd());
				tn->getProcState()->setClientAddress(tn->clientAddress());
				tn->getProcState()->setServerAddress(tn->serverAddress());
				/* Session starts when a new processing state is created. */
				unsigned long sr_num = std::atomic_load(&(this->_sr_srl_num));
				tn->setBaseSRSrlNum(sr_num);
			}

			{
				justEnqueue(tn);
			}

			{
				ev_io * socket_watcher_ptr = 0;
				socket_watcher_ptr = tn->getSocketWatcher();

				ev_io_stop(this->_loop, socket_watcher_ptr);
				ev_clear_pending(this->_loop, socket_watcher_ptr);
				tn->setState(EVAcceptedStreamSocket::NOT_WAITING);
			}
		}
	}
	catch (std::exception & e) {
		//DEBUGPOINT("Here ret = [%zd]\n", ret);
		ret = -1;
	}
	if ((ret <= 0) || errno) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		}
		else {
			//errorWhileReceiving(ss.impl()->sockfd(), true);
			if (!tn->shutdownInitiated() || !tn->resDataAvlbl()) {
				/* i, a
				 * 0, 0 => ENTER
				 * 0, 1 => ENTER
				 * 1, 0 => ENTER
				 * 1, 1 => DONT ENTER
				 */
				ev_io * socket_watcher_ptr = 0;
				socket_watcher_ptr = tn->getSocketWatcher();
				if (socket_watcher_ptr && ev_is_active(socket_watcher_ptr)) {
					ev_io_stop(this->_loop, socket_watcher_ptr);
					ev_clear_pending(this->_loop, socket_watcher_ptr);
				}
				//DEBUGPOINT("SHUTTING DOWN HERE\n");
				errorWhileReceiving(ss.impl()->sockfd(), true);
			}
			else {
				if (tn->getState() == EVAcceptedStreamSocket::WAITING_FOR_READ) {
					tn->setState(EVAcceptedStreamSocket::NOT_WAITING);
				}
				else if (tn->getState() == EVAcceptedStreamSocket::WAITING_FOR_READWRITE) {
					tn->setState(EVAcceptedStreamSocket::WAITING_FOR_WRITE);
				}
				//DEBUGPOINT("NOT SHUTTING DOWN HERE\n");
				sendDataOnAccSocket(tn, false);
			}
		}
	}

	return ret;
}

ssize_t EVTCPServer::handleAccSocketReadable(StreamSocket & ss, const bool& ev_occured)
{
	ssize_t ret = 0;
	size_t received_bytes = 0;
	EVAcceptedStreamSocket *tn = getTn(ss.impl()->sockfd());
	tn->setTimeOfLastUse();
	_ssLRUList.move(tn);
	if (tn->getSockMode() == EVAcceptedStreamSocket::WEBSOCKET_MODE) {
		return EVTCPServer::handleAccWebSocketReadable(ss, ev_occured);
	}

	{
		ssize_t ret1 = 0;
		int count = 0;
		do {
			count ++;
			void * buffer = malloc(TCP_BUFFER_SIZE);
			memset(buffer,0,TCP_BUFFER_SIZE);
			//ret1 = receiveData(ss.impl()->sockfd(), buffer, TCP_BUFFER_SIZE);
			ret1 = receiveData(ss, buffer, TCP_BUFFER_SIZE);
			//DEBUGPOINT("Here ret = [%zd] errno = [%d]\n", ret1, errno);
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

handleAccSocketReadable_finally:
	if ((ret >=0) && tn->reqDataAvlbl()) {
		if (!(tn->getProcState()) ||
			( tn->getProcState()->needMoreData() &&
			  ( (tn->getProcState()->newDataProcessed()) ||
				(!(tn->getProcState()->newDataProcessed()) && (received_bytes > 0))
			  )
			)
			) {
			if (!(tn->getProcState())) {
				tn->setProcState(_pConnectionFactory->createReqProcState(this));
				//DEBUGPOINT("Created processing state %p for %d\n", tn->getProcState(), tn->getSockfd());
				tn->getProcState()->setClientAddress(tn->clientAddress());
				tn->getProcState()->setServerAddress(tn->serverAddress());
				/* Session starts when a new processing state is created. */
				unsigned long sr_num = std::atomic_load(&(this->_sr_srl_num));
				tn->setBaseSRSrlNum(sr_num);
			}
			justEnqueue(tn);

			/* If data is available, and a task has been enqueued.
			 * It is not OK to cleanup the socket.
			 * It is proper to process whatever data is still there
			 * and then close the socket at a later time.
			 * */
			ret = 1;
		} 
		else {
			/* This is a case of receiving data that is not asked by the
			 * server.
			 * */
		}
	}


	/* ret will be 0 after recv even on a tickled socket
	 * in case of SSL handshake.
	 * */
	//DEBUGPOINT("Here\n");
	if (ret > 0) {
		ev_io * socket_watcher_ptr = 0;
		socket_watcher_ptr = tn->getSocketWatcher();
		if (tn->getState() == EVAcceptedStreamSocket::WAITING_FOR_READ) {
			ev_io_stop(this->_loop, socket_watcher_ptr);
			ev_clear_pending(this->_loop, socket_watcher_ptr);
			tn->setState(EVAcceptedStreamSocket::NOT_WAITING);
		}
		else if (tn->getState() == EVAcceptedStreamSocket::WAITING_FOR_READWRITE) {
			ev_io_stop(this->_loop, socket_watcher_ptr);
			ev_clear_pending(this->_loop, socket_watcher_ptr);
			ev_io_init (socket_watcher_ptr, async_stream_socket_cb_1, ss.impl()->sockfd(), EV_WRITE);
			ev_io_start (this->_loop, socket_watcher_ptr);
			tn->setState(EVAcceptedStreamSocket::WAITING_FOR_WRITE);
		}
		else {
			/* It should not come here otherwise. */
			DEBUGPOINT("SHOULD NOT HAVE REACHED HERE %d\n", tn->getState());
			std::abort();
		}
	}
	else if (ret < 0)  {
		//DEBUGPOINT("Here for %d\n", tn->getSockfd());
		tn->setSockInError();

		// If handleAccSocketReadable is called not from event loop (ev_occured = true)
		// Cleaning up of socket will lead to context being lost completely.
		// It sould be marked as being in error and the housekeeping to be done at
		// an approporiate time.
		if (!tn->shutdownInitiated() || !tn->resDataAvlbl()) {
			/* i, a
			 * 0, 0 => ENTER
			 * 0, 1 => ENTER
			 * 1, 0 => ENTER
			 * 1, 1 => DONT ENTER
			 */
			ev_io * socket_watcher_ptr = 0;
			socket_watcher_ptr = tn->getSocketWatcher();
			if (socket_watcher_ptr && ev_is_active(socket_watcher_ptr)) {
				ev_io_stop(this->_loop, socket_watcher_ptr);
				ev_clear_pending(this->_loop, socket_watcher_ptr);
			}
			//DEBUGPOINT("SHUTTING DOWN HERE\n");
			errorWhileReceiving(ss.impl()->sockfd(), true);
		}
		else {
			if (tn->getState() == EVAcceptedStreamSocket::WAITING_FOR_READ) {
				tn->setState(EVAcceptedStreamSocket::NOT_WAITING);
			}
			else if (tn->getState() == EVAcceptedStreamSocket::WAITING_FOR_READWRITE) {
				tn->setState(EVAcceptedStreamSocket::WAITING_FOR_WRITE);
			}
			//DEBUGPOINT("NOT SHUTTING DOWN HERE\n");
			sendDataOnAccSocket(tn, false);
		}
	}

	return ret;
}

void EVTCPServer::dataReadyForSend(int fd)
{
	/* Enque the socket */
	_queue.enqueueNotification(new EVTCPServerNotification(fd,
													EVTCPServerNotification::DATA_FOR_SEND_READY));

	/* And then wake up the loop calls event_notification_on_downstream_socket */
	//DEBUGPOINT("FROM HERE\n");
	ev_async_send(this->_loop, this->_stop_watcher_ptr3);
	return;
}

void EVTCPServer::receivedDataConsumed(int fd)
{
	/* Enque the socket */
	//STACK_TRACE();
	_queue.enqueueNotification(new EVTCPServerNotification(fd,
													EVTCPServerNotification::REQDATA_CONSUMED));

	/* And then wake up the loop calls event_notification_on_downstream_socket */
	//DEBUGPOINT("FROM HERE\n");
	ev_async_send(this->_loop, this->_stop_watcher_ptr3);
	return;
}

void EVTCPServer::errorWhileSending(poco_socket_t fd, bool connInErr)
{
	/* Enque the socket */
	//_queue.enqueueNotification(new EVTCPServerNotification(streamSocket,fd,true));
	/* The StreamSocket Received in this function may not contain the desirable value.
	 * It could have become -1.
	 * */
	_queue.enqueueNotification(new EVTCPServerNotification(fd,
													EVTCPServerNotification::ERROR_WHILE_SENDING));

	/* And then wake up the loop calls event_notification_on_downstream_socket */
	//DEBUGPOINT("FROM HERE\n");
	ev_async_send(this->_loop, this->_stop_watcher_ptr3);
	return;
}

void EVTCPServer::errorWhileReceiving(poco_socket_t fd, bool connInErr)
{
	/* Enque the socket */
	//_queue.enqueueNotification(new EVTCPServerNotification(streamSocket,fd,true));
	/* The StreamSocket Received in this function may not contain the desirable value.
	 * It could have become -1.
	 * */
	_queue.enqueueNotification(new EVTCPServerNotification(fd,
													EVTCPServerNotification::ERROR_WHILE_RECEIVING));

	/* And then wake up the loop calls event_notification_on_downstream_socket */
	//DEBUGPOINT("FROM HERE\n");
	ev_async_send(this->_loop, this->_stop_watcher_ptr3);
	return;
}

void EVTCPServer::errorInAuxProcesing(poco_socket_t fd, bool connInErr)
{
	/* Enque the socket */
	//_queue.enqueueNotification(new EVTCPServerNotification(streamSocket,fd,true));
	/* The StreamSocket Received in this function may not contain the desirable value.
	 * It could have become -1.
	 * */
	//DEBUGPOINT("Here for %d\n", fd);
	//STACK_TRACE();
	_queue.enqueueNotification(new EVTCPServerNotification(fd,
													EVTCPServerNotification::ERROR_IN_AUX_PROCESSING));

	/* And then wake up the loop calls event_notification_on_downstream_socket */
	//DEBUGPOINT("FROM HERE\n");
	ev_async_send(this->_loop, this->_stop_watcher_ptr3);
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

	/* And then wake up the loop calls event_notification_on_downstream_socket */
	//DEBUGPOINT("FROM HERE\n");
	ev_async_send(this->_loop, this->_stop_watcher_ptr3);
	return;
}

void EVTCPServer::monitorDataOnCLFd(EVAcceptedStreamSocket *tn)
{
	ev_io * socket_watcher_ptr = 0;
	if (tn->sockInError()) {
		DEBUGPOINT("SOCK IN ERROR RETURNING for %d\n", tn->getSockfd());
		return;
	}
	socket_watcher_ptr = tn->getSocketWatcher();
	StreamSocket ss = tn->getStreamSocket();

	{
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

			ev_io_stop(this->_loop, socket_watcher_ptr);
			ev_clear_pending(this->_loop, socket_watcher_ptr);
			//ev_io_set (socket_watcher_ptr, ss.impl()->sockfd(), EV_READ);
			ev_io_init(socket_watcher_ptr, async_stream_socket_cb_1, ss.impl()->sockfd(), events);
			ev_io_start (this->_loop, socket_watcher_ptr);
		}
	}

	if (tn->reqDataAvlbl()) {
		/* There is residual data on socket.
		 * This can be a cause for unnecessary thread context switching
		 * opportunity for optimization.
		 * */
		handleCLFdReadable(ss, false);
	}
	else {
		// TBD TO ADD SOCKET TO TIME OUT MONITORING LIST
	}

	return;
}

void EVTCPServer::monitorDataOnAccSocket(EVAcceptedStreamSocket *tn)
{
	ev_io * socket_watcher_ptr = 0;
	if (tn->sockInError()) {
		DEBUGPOINT("SOCK IN ERROR RETURNING for %d\n", tn->getSockfd());
		return;
	}
	if (EVAcceptedStreamSocket::TO_BE_CLOSED == tn->getState()) {
		DEBUGPOINT("CLOSING SOCKET\n");
		clearAcceptedSocket(tn->getSockfd());
		return ;
	}

	//DEBUGPOINT("newpendingCSEvents() = [%d]\n", tn->newpendingCSEvents());

	socket_watcher_ptr = tn->getSocketWatcher();
	StreamSocket ss = tn->getStreamSocket();

	{
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

			ev_io_stop(this->_loop, socket_watcher_ptr);
			ev_clear_pending(this->_loop, socket_watcher_ptr);
			//ev_io_set (socket_watcher_ptr, ss.impl()->sockfd(), EV_READ);
			ev_io_init(socket_watcher_ptr, async_stream_socket_cb_1, ss.impl()->sockfd(), events);
			ev_io_start (this->_loop, socket_watcher_ptr);
		}
	}

	if (tn->reqDataAvlbl()) {
		/* There is residual data on socket.
		 * This can be a cause for unnecessary thread context switching
		 * opportunity for optimization.
		 * */
		handleAccSocketReadable(ss, false);
	}
	else {
		// TBD TO ADD SOCKET TO TIME OUT MONITORING LIST
	}


	return;
}

void EVTCPServer::sendDataOnReturnPipe(EVAcceptedStreamSocket *tn, int OnEvent)
{
	ev_io * socket_watcher_ptr = 0;
	strms_io_cb_ptr_type cb_ptr = 0;

	socket_watcher_ptr = tn->getSocketWatcher();
	if (!socket_watcher_ptr) std::abort();

	cb_ptr = (strms_io_cb_ptr_type)socket_watcher_ptr->data;

	/* If socket is not writable make it so. */
	//DEBUGPOINT("Here state %d for %d\n", tn->getState(), tn->getSockfd());
	if ((tn->getState() == EVAcceptedStreamSocket::NOT_WAITING) ||
		 tn->getState() == EVAcceptedStreamSocket::WAITING_FOR_READ) {
		int events = 0;
		if (tn->getState() == EVAcceptedStreamSocket::WAITING_FOR_READ) {
			//STACK_TRACE();
			//DEBUGPOINT("Here for socket %d\n", tn->getSockfd());
			events = EVAcceptedStreamSocket::WAITING_FOR_READWRITE;
			tn->setState(EVAcceptedStreamSocket::WAITING_FOR_READWRITE);
		}
		else {
			//STACK_TRACE();
			//DEBUGPOINT("Here for socket %d\n", tn->getSockfd());
			events = EVAcceptedStreamSocket::WAITING_FOR_WRITE;
			tn->setState(EVAcceptedStreamSocket::WAITING_FOR_WRITE);
		}
		cb_ptr->socketWritable = &EVTCPServer::handleCLWrFdWritable;

		ev_io_stop(this->_loop, socket_watcher_ptr);
		ev_clear_pending(this->_loop, socket_watcher_ptr);
		ev_io_init (socket_watcher_ptr, async_stream_socket_cb_1, tn->getSockfd(), events);
		ev_io_start (this->_loop, socket_watcher_ptr);

	}

	StreamSocket ss = tn->getStreamSocket();
	handleCLWrFdWritable(ss, false);

	return;
}

void EVTCPServer::sendDataOnAccSocket(EVAcceptedStreamSocket *tn, int OnEvent)
{
	ev_io * socket_watcher_ptr = 0;
	strms_io_cb_ptr_type cb_ptr = 0;

	socket_watcher_ptr = tn->getSocketWatcher();
	if (!socket_watcher_ptr) std::abort();

	cb_ptr = (strms_io_cb_ptr_type)socket_watcher_ptr->data;

	/* If socket is not writable make it so. */
	//DEBUGPOINT("Here state %d for %d\n", tn->getState(), tn->getSockfd());
	if ((tn->getState() == EVAcceptedStreamSocket::NOT_WAITING) ||
		 tn->getState() == EVAcceptedStreamSocket::WAITING_FOR_READ) {
		int events = 0;
		if (tn->getState() == EVAcceptedStreamSocket::WAITING_FOR_READ) {
			//STACK_TRACE();
			//DEBUGPOINT("Here for socket %d\n", tn->getSockfd());
			events = EVAcceptedStreamSocket::WAITING_FOR_READWRITE;
			tn->setState(EVAcceptedStreamSocket::WAITING_FOR_READWRITE);
		}
		else {
			//STACK_TRACE();
			//DEBUGPOINT("Here for socket %d\n", tn->getSockfd());
			events = EVAcceptedStreamSocket::WAITING_FOR_WRITE;
			tn->setState(EVAcceptedStreamSocket::WAITING_FOR_WRITE);
		}
		cb_ptr->socketWritable = &EVTCPServer::handleAccSocketWritable;

		ev_io_stop(this->_loop, socket_watcher_ptr);
		ev_clear_pending(this->_loop, socket_watcher_ptr);
		ev_io_init (socket_watcher_ptr, async_stream_socket_cb_1, tn->getSockfd(), events);
		ev_io_start (this->_loop, socket_watcher_ptr);

	}

	StreamSocket ss = tn->getStreamSocket();
	handleAccSocketWritable(ss, false);

	return;
}

void EVTCPServer::somethingHappenedInAnotherThread(const bool& ev_occured)
{
	//DEBUGPOINT("Here\n");
	ev_io * socket_watcher_ptr = 0;
	AutoPtr<Notification> pNf = 0;
	for  (pNf = _queue.dequeueNotification(); pNf ; pNf = _queue.dequeueNotification()) {
		EVTCPServerNotification * pcNf = dynamic_cast<EVTCPServerNotification*>(pNf.get());

		EVTCPServerNotification::what event = pcNf->getEvent();
		EVAcceptedStreamSocket *tn = getTn(pcNf->sockfd());
		if (!tn) {
			/* This should never happen. */
			DEBUGPOINT("Did not find entry in _accssColl for [%d] for event = [%d]\n", pcNf->sockfd(), event);

			/* Multiple events can get queued for a socket from another thread.
			 * In the meanwhile, it is possible that the socket gets into an error state
			 * due to various conditions, one such is wrong data format and the protocol
			 * handler fails. This condition will lead to socket getting closed.
			 * Subsequent events after closing of the socket must be ignored.
			 * */
			continue;
		}
		//DEBUGPOINT("Here\n");
		socket_watcher_ptr = getTn(pcNf->sockfd())->getSocketWatcher();
		StreamSocket ss = tn->getStreamSocket();

		/* If some error has been noticed on this socket, dispose it off cleanly
		 * over here
		 * */
		if ((event == EVTCPServerNotification::REQDATA_CONSUMED) && (tn->sockInError())) {
			//DEBUGPOINT("Here for %d\n", tn->getSockfd());
			event = EVTCPServerNotification::ERROR_IN_PROCESSING;
		}

		//DEBUGPOINT("Here event = %d\n", event);
		switch (event) {
			case EVTCPServerNotification::REQDATA_CONSUMED:
				//DEBUGPOINT("REQDATA_CONSUMED on socket %d\n", ss.impl()->sockfd());
				tn->setSockFree();
				if (PROCESS_COMPLETE <= (tn->getProcState()->getState())) {
					//DEBUGPOINT("REMOVING STATE of %d\n", ss.impl()->sockfd());
					std::map<int,int>& subscriptions = tn->getProcState()->getFileEvtSubscriptions();
					for (auto it = subscriptions.begin(); it != subscriptions.end(); ++it) {
						//DEBUGPOINT("Here %d\n", it->first);
						_file_evt_subscriptions.erase(it->first);
					}
					subscriptions.clear();
					if (this->_mode == SERVER_MODE) {
						DEBUGPOINT("Deleted processing state %p for %d\n", tn->getProcState(), tn->getSockfd());
					}
					tn->deleteState();
					/* Should reset of number of CS events be done at all
					 * tn->newresetNumCSEvents();
					 * */
					tn->setWaitingTobeEnqueued(false);
					//DEBUGPOINT("COMPLETED PROCESSING # CS EVENTS %d\n",tn-newPendingCSEvents()); 
				}
				//else DEBUGPOINT("RETAINING STATE\n");
				switch (tn->getSockMode()) {
					case EVAcceptedStreamSocket::SERVER_MODE:
						//DEBUGPOINT("newpendingCSEvents() = [%d]\n", tn->newpendingCSEvents());
						sendDataOnAccSocket(tn, event);
						break;
					case EVAcceptedStreamSocket::WEBSOCKET_MODE:
						//DEBUGPOINT("newpendingCSEvents() = [%d]\n", tn->newpendingCSEvents());
						// The worker thread takes care of 
						// reading and writing data from and to
						// socket in case of WEBSOCKET_MODE
						break;
					case EVAcceptedStreamSocket::COMMAND_LINE_MODE:
						sendDataOnReturnPipe(tn, event);
						break;
					default:
						DEBUGPOINT("Invalid socket mode [%d]\n", tn->getSockMode());
						std::abort();

				}
				/* SOCK IS FREE HERE */
				if (tn->getProcState() && tn->waitingTobeEnqueued()) {

					/* SOCK HAS BECOME BUSY HERE */
					srCompleteEnqueue(tn);
				}
				//DEBUGPOINT("Here\n");
				if (!tn->getProcState() && tn->sockInError()) {
					/* If processing state is present, another thread can still be processing
					 * the request, hence cannot complete housekeeping.
					 * */
					DEBUGPOINT("clearing for %d\n", tn->getSockfd());
					clearAcceptedSocket(pcNf->sockfd());
				}
				else {
					//DEBUGPOINT("Here for %d\n", tn->getSockfd());

					/* SHOULD MONITOR FOR MORE DATA ONLY IF SOCKET IS FREE */
					if (!(tn->sockBusy())) {
						if (this->_mode == SERVER_MODE) {
							/* Put code here to handle the case when
							 * an existing socket is upgraded to another protocol.
							 * Switching should take place after the data is
							 * completely sent to the client.
							 */
							if (!tn->resDataAvlbl() && tn->getSockUpgradeTo()) {
								switch (tn->getSockMode()) {
									case EVAcceptedStreamSocket::SERVER_MODE:
										switch (tn->getSockUpgradeTo()) {
											case EVAcceptedStreamSocket::WEBSOCKET:
												tn->getStreamSocketPtr()->impl()->managed(true);
												tn->setSockMode(EVAcceptedStreamSocket::WEBSOCKET_MODE);
												break;
											case EVAcceptedStreamSocket::HTTP2:
												DEBUGPOINT("HTTP2 not implemented\n");
												std::abort();
												break;
											case EVAcceptedStreamSocket::NONE:
												break;
											default:
												DEBUGPOINT("Invalid upgrade to [%d]\n", tn->getSockUpgradeTo());
												std::abort();

										}
										break;
									default:
										break;

								}
								/*
								 * HTTP2 enhancement
								 * Get socket fd out
								 * Clear tn
								 * Create a different kind of acc socket
								 * which continuously reads data and
								 * handles on data available differently.
								 */
								if (tn->getSockMode() == EVAcceptedStreamSocket::WEBSOCKET_MODE) {
									monitorDataOnAccSocket(tn);
								}
								else if (tn->getSockMode() == EVAcceptedStreamSocket::HTTP2_MODE) {
									DEBUGPOINT("HTTP2 not yet implemented\n");
									std::abort();
								}
								else {
									DEBUGPOINT("Protocol not supported\n");
									std::abort();
								}
							}
							else {
								monitorDataOnAccSocket(tn);
							}
						}
						else {
							monitorDataOnCLFd(tn);
						}
					}
				}
				break;
			case EVTCPServerNotification::DATA_FOR_SEND_READY:
				//DEBUGPOINT("DATA_FOR_SEND_READY on socket %d sockMode = [%d]\n", ss.impl()->sockfd(), tn->getSockMode());
				if (tn->getSockMode() == EVAcceptedStreamSocket::COMMAND_LINE_MODE) {
					sendDataOnReturnPipe(tn, event);
				}
				else if (tn->getSockMode() == EVAcceptedStreamSocket::SERVER_MODE) {
					sendDataOnAccSocket(tn, event);
				}
				//else if (tn->getSockMode() == EVAcceptedStreamSocket::WEBSOCKET_MODE) {
					/* Nothing to do in case of WEBSOCKET MODE
					 * Since as per the present design, all websocket
					 * communication will be handled in the worker 
					 * thread only
					 */
					//DEBUGPOINT("Here\n");
				//}
				else {
					DEBUGPOINT("Invalid Socket Mode\n");
					std::abort();
				}
				break;
			case EVTCPServerNotification::ERROR_IN_PROCESSING:
				//DEBUGPOINT("ERROR_IN_PROCESSING on socket %d\n", pcNf->sockfd());
				tn->setSockFree();
				if (tn->newpendingCSEvents()) {
					//DEBUGPOINT("RETAINING  ACC SOCK\n");
					//DEBUGPOINT("Here for %d\n", tn->getSockfd());
					tn->setSockInError();
				}
				else {
					//DEBUGPOINT("CLEARING ACC SOCK %d\n", pcNf->sockfd());
					if (tn->getProcState()) {
						std::map<int,int>& subscriptions = tn->getProcState()->getFileEvtSubscriptions();
						for (auto it = subscriptions.begin(); it != subscriptions.end(); ++it) {
							//DEBUGPOINT("Here %d\n", it->first);
							_file_evt_subscriptions.erase(it->first);
						}
						subscriptions.clear();
					}
					//DEBUGPOINT("clearing for %d\n", tn->getSockfd());
					clearAcceptedSocket(pcNf->sockfd());
				}
				break;

			case EVTCPServerNotification::ERROR_IN_AUX_PROCESSING:
				//DEBUGPOINT("ERROR_IN_AUX_PROCESSING on socket %d\n", pcNf->sockfd());
				if (tn->newpendingCSEvents() || tn->sockBusy()) {
					//DEBUGPOINT("RETAINING  ACC SOCK\n");
					//DEBUGPOINT("Here for %d\n", tn->getSockfd());
					tn->setSockInError();
				}
				else {
					//DEBUGPOINT("CLEARING ACC SOCK %d\n", pcNf->sockfd());
					if (tn->getProcState()) {
						std::map<int,int>& subscriptions = tn->getProcState()->getFileEvtSubscriptions();
						for (auto it = subscriptions.begin(); it != subscriptions.end(); ++it) {
							//DEBUGPOINT("Here %d\n", it->first);
							_file_evt_subscriptions.erase(it->first);
						}
						subscriptions.clear();
					}
					//DEBUGPOINT("clearing for %d\n", tn->getSockfd());
					clearAcceptedSocket(pcNf->sockfd());
				}
				break;

			/* The following 2 cases are generated within the thread of
			 * EVTCPServer. Whereas the above ones are resultant of some
			 * event in the worker thread.
			 * */

			case EVTCPServerNotification::ERROR_WHILE_SENDING:
				//DEBUGPOINT("ERROR_WHILE_SENDING on socket %d\n", pcNf->sockfd());
			case EVTCPServerNotification::ERROR_WHILE_RECEIVING:
				//DEBUGPOINT("ERROR_WHILE_RECEIVING on socket %d\n", pcNf->sockfd());
				//DEBUGPOINT("SOCK [%d] BUSY = %d\n", pcNf->sockfd(), tn->sockBusy());
				//DEBUGPOINT("SOCK [%d] peinding CS events = %d\n", pcNf->sockfd(), tn->newpendingCSEvents());
				if (!(tn->sockBusy()) && !(tn->newpendingCSEvents())) {
					//DEBUGPOINT("CLEARING ACC SOCK tn sock = %d, pcNf sock = %d\n", tn->getSockfd(), pcNf->sockfd());
					if (tn->getProcState()) {
						std::map<int,int>& subscriptions = tn->getProcState()->getFileEvtSubscriptions();
						for (auto it = subscriptions.begin(); it != subscriptions.end(); ++it) {
							//DEBUGPOINT("Here %d\n", it->first);
							_file_evt_subscriptions.erase(it->first);
						}
						subscriptions.clear();
					}
					//DEBUGPOINT("clearing for %d\n", tn->getSockfd());
					clearAcceptedSocket(pcNf->sockfd());
				}
				else {
					//DEBUGPOINT("RETAINING  ACC SOCK\n");
					//DEBUGPOINT("Here for %d\n", tn->getSockfd());
					tn->setSockInError();
				}
				break;
			default:
				break;
		}
		pcNf = NULL;
	}

	return;
}

EVAcceptedStreamSocket*  EVTCPServer::createEVAccSocket(StreamSocket& ss)
{
	int fd = 0;
#if defined(POCO_OS_FAMILY_UNIX)
	if (ss.address().family() != AddressFamily::UNIX_LOCAL)
#endif
	{
		ss.setNoDelay(true);
	}

	EVAcceptedStreamSocket * acceptedSock = new EVAcceptedStreamSocket(ss);
	acceptedSock->setClientAddress(ss.peerAddress());
	acceptedSock->setServerAddress(ss.address());
	acceptedSock->setEventLoop(this->_loop);

	{
		ev_io * socket_watcher_ptr = 0;
		strms_io_cb_ptr_type cb_ptr = 0;

		socket_watcher_ptr = (ev_io*)malloc(sizeof(ev_io));
		memset(socket_watcher_ptr,0,sizeof(ev_io));

		cb_ptr = (strms_io_cb_ptr_type) malloc(sizeof(strms_io_cb_struct_type));
		memset(cb_ptr,0,sizeof(strms_io_cb_struct_type));

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
		ev_io_start (this->_loop, socket_watcher_ptr);
	}

	return acceptedSock;
}

void EVTCPServer::handleConnReq(const bool& ev_occured)
{
	EVAcceptedStreamSocket * ptr = _ssLRUList.getLast();
	while (ptr && (_accssColl.size()  >= _numConnections)) {
		if (ptr->getProcState()) {
			ptr = ptr->getPrevPtr();
			continue;
		}
		ev_io_stop(this->_loop, ptr->getSocketWatcher());
		ev_clear_pending(this->_loop, ptr->getSocketWatcher());
		DEBUGPOINT("Here\n");
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
			createEVAccSocket(ss);
		}
		else {
			DEBUGPOINT("CONN REQUEST REJECTED\n");
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

void EVTCPServer::handlePeriodicWakeup(const bool& ev_occured)
{
	EVAcceptedStreamSocket *tn = 0;

	tn = _ssLRUList.getFirst();
	while (tn) {
		/* Handle all those sockets which are waiting for read while
		 * processing of input data is in progress.
		 * */

		/* This O(n) parsing can be a problem, if there are hundreds
		 * of thousands of connections.
		 * */
		if ((EVAcceptedStreamSocket::WAITING_FOR_READWRITE == tn->getState() ||
			EVAcceptedStreamSocket::WAITING_FOR_READ == tn->getState()) &&
			(tn->getProcState() && (tn->getProcState()->needMoreData()))) {
			struct timeval tv;
			gettimeofday(&tv,0);
			if ((tv.tv_sec - tn->getTimeOfLastUse()) > _receiveTimeOut) {
				DEBUGPOINT("TIMER EVENT OCCURED for socket %d\n", tn->getSockfd());
				ev_io_stop(this->_loop, tn->getSocketWatcher());
				ev_clear_pending(this->_loop, tn->getSocketWatcher());
				errorInReceivedData(tn->getSockfd(),true);
			}
		}
		tn= tn->getNextPtr();
	}
	return;
}

ssize_t EVTCPServer::handleCLFdReadable(StreamSocket & ss, const bool& ev_occured)
{
	ssize_t ret = 0;
	size_t received_bytes = 0;
	EVAcceptedStreamSocket *tn = getTn(ss.impl()->sockfd());
	tn->setTimeOfLastUse();
	_ssLRUList.move(tn);

	{
		ssize_t ret1 = 0;
		int count = 0;
		do {
			count ++;
			void * buffer = malloc(TCP_BUFFER_SIZE);
			memset(buffer,0,TCP_BUFFER_SIZE);
			ret1 = readData(ss.impl()->sockfd(), buffer, TCP_BUFFER_SIZE);
			if (ret1 >0) {
				tn->pushReqData(buffer, (size_t)ret1);
				ret += ret1;
				received_bytes += ret1;
				if (received_bytes > TCP_BUFFER_SIZE) {
					DEBUGPOINT("Commands of lentgth greater than [%d] not supported\n", TCP_BUFFER_SIZE);
					std::abort();
				}
			}
			else {
				free(buffer);
				if (ret1 < 0) {
					ret = -1;
				}
			}
		} while(!_blocking && ret1>0);
	}

	//std::abort();

handleCLFdReadable_finally:
	if ((ret >=0) && tn->reqDataAvlbl()) {
		if (!(tn->getProcState()) ||
			( tn->getProcState()->needMoreData() &&
			  ( (tn->getProcState()->newDataProcessed()) ||
				(!(tn->getProcState()->newDataProcessed()) && (received_bytes > 0))
			  )
			)
			) {
			if (!(tn->getProcState())) {
				tn->setProcState(_pConnectionFactory->createCLProcState(this));
				tn->getProcState()->setMode(EVAcceptedStreamSocket::COMMAND_LINE_MODE);
				//DEBUGPOINT("Created processing state %p for %d\n", tn->getProcState(), tn->getSockfd());
				tn->getProcState()->setClientAddress(tn->clientAddress());
				tn->getProcState()->setServerAddress(tn->serverAddress());
				/* Session starts when a new processing state is created. */
				unsigned long sr_num = std::atomic_load(&(this->_sr_srl_num));
				tn->setBaseSRSrlNum(sr_num);
			}
			justEnqueue(tn);

			/* If data is available, and a task has been enqueued.
			 * It is not OK to cleanup the socket.
			 * It is proper to process whatever data is still there
			 * and then close the socket at a later time.
			 * */
			ret = 1;
		} 
		else {
			/* This is a case of receiving data that is not asked by the
			 * server.
			 * */
		}
	}


	/* ret will be 0 after recv even on a tickled socket
	 * in case of SSL handshake.
	 * */
	if (ret > 0) {
		ev_io * socket_watcher_ptr = 0;
		socket_watcher_ptr = tn->getSocketWatcher();
		if (tn->getState() == EVAcceptedStreamSocket::WAITING_FOR_READ) {
			ev_io_stop(this->_loop, socket_watcher_ptr);
			ev_clear_pending(this->_loop, socket_watcher_ptr);
			tn->setState(EVAcceptedStreamSocket::NOT_WAITING);
		}
		else if (tn->getState() == EVAcceptedStreamSocket::WAITING_FOR_READWRITE) {
			ev_io_stop(this->_loop, socket_watcher_ptr);
			ev_clear_pending(this->_loop, socket_watcher_ptr);
			ev_io_init (socket_watcher_ptr, async_stream_socket_cb_1, ss.impl()->sockfd(), EV_WRITE);
			ev_io_start (this->_loop, socket_watcher_ptr);
			tn->setState(EVAcceptedStreamSocket::WAITING_FOR_WRITE);
		}
		else {
			/* It should not come here otherwise. */
			DEBUGPOINT("SHOULD NOT HAVE REACHED HERE %d\n", tn->getState());
			std::abort();
		}
	}
	else if (ret < 0)  {
		//DEBUGPOINT("Here for %d\n", tn->getSockfd());
		tn->setSockInError();

		// If handleAccSocketReadable is called not from event loop (ev_occured = true)
		// Cleaning up of socket will lead to context being lost completely.
		// It sould be marked as being in error and the housekeeping to be done at
		// an approporiate time.
		{
			ev_io * socket_watcher_ptr = 0;
			socket_watcher_ptr = tn->getSocketWatcher();
			if (socket_watcher_ptr && ev_is_active(socket_watcher_ptr)) {
				ev_io_stop(this->_loop, socket_watcher_ptr);
				ev_clear_pending(this->_loop, socket_watcher_ptr);
			}
		}
		errorWhileReceiving(ss.impl()->sockfd(), true);
	}

	return ret;
}

#include <poll.h>

void EVTCPServer::addCLPrimaryFdToAcceptedList(int fd, int wr_fd)
{
	try {

		EVAcceptedStreamSocket * acceptedSock = new EVAcceptedStreamSocket(fd, wr_fd);
		acceptedSock->setEventLoop(this->_loop);

		{
			ev_io * socket_watcher_ptr = 0;
			strms_io_cb_ptr_type cb_ptr = 0;

			socket_watcher_ptr = (ev_io*)malloc(sizeof(ev_io));
			memset(socket_watcher_ptr,0,sizeof(ev_io));

			cb_ptr = (strms_io_cb_ptr_type) malloc(sizeof(strms_io_cb_struct_type));
			memset(cb_ptr,0,sizeof(strms_io_cb_struct_type));

			acceptedSock->setSocketWatcher(socket_watcher_ptr);
			acceptedSock->getStreamSocketPtr()->setFd(fd);
			_accssColl[fd] = acceptedSock;
			acceptedSock->setTimeOfLastUse();
			_ssLRUList.add(acceptedSock);

			cb_ptr->objPtr = this;
			cb_ptr->dataAvailable = &EVTCPServer::handleCLFdReadable;
			/* The below line is a dummy and a hack to avoid SIGSEGV */
			cb_ptr->ssPtr = acceptedSock->getStreamSocketPtr();
			/* The above line is a dummy and a hack to avoid SIGSEGV */
			socket_watcher_ptr->data = (void*)cb_ptr;

			acceptedSock->setState(EVAcceptedStreamSocket::WAITING_FOR_READ);

			// Make the socket non blocking.
			if (!_blocking) {
				fcntl(fd, F_SETFL, O_NONBLOCK);
			}

			ev_io_init (socket_watcher_ptr, async_stream_socket_cb_1, fd, EV_READ);
			ev_io_start (this->_loop, socket_watcher_ptr);
			errno=0;
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

}

static void fatal_error (const char *msg) noexcept
{
	DEBUGPOINT("IN FATAL_ERROR\n");
	perror (msg);
	std::abort ();
}


void EVTCPServer::run()
{
	ev_io socket_watcher;
	ev_async stop_watcher_1;
	ev_async stop_watcher_2;
	ev_async stop_watcher_3;
	ev_async dns_watcher;
	ev_async gen_task_compl_watcher;
	ev_async file_evt_watcher;
	ev_timer timeout_watcher;
	double timeout = 0.00001;

	this->_thread_pool = create_thread_pool(DEFAULT_NUM_AUXJOB_THREADS);
	//this->_thread_pool = create_thread_pool(1);

	ef_set_thrpool(this->_thread_pool);
	ef_init();
	ef_set_cb_func(file_operation_completion, (void *)this);

	this->_loop = EV_DEFAULT;

	memset(&(socket_watcher), 0, sizeof(ev_io));	// Sinvle channel to monitor incoming
													// connection requests and 
													// events on accepted sockets
	memset(&(stop_watcher_1), 0, sizeof(ev_async)); // Channel to end the loop
	memset(&(stop_watcher_2), 0, sizeof(ev_async)); // Channel for children threads
													// to request services from main loop
	memset(&(stop_watcher_3), 0, sizeof(ev_async)); // Channel for the asigned worker thread
													// to coordinate with main thread
													// for various request processing events
	memset(&(dns_watcher),0,sizeof(ev_async));		// Channel to indicate resolution of a name
													// via DNS service
	memset(&(gen_task_compl_watcher),0,sizeof(ev_async));
													// Channel to handle event of completion
													// of generic tasks void* (*task)(void*)
	memset(&(file_evt_watcher),0,sizeof(ev_async)); // Channel to monitor comletion of
													// FILE IO events
	memset(&(timeout_watcher), 0, sizeof(ev_timer));// Channel to monitor periodic timer
													// for GC, etc...

	this->_stop_watcher_ptr1 = &(stop_watcher_1);
	this->_stop_watcher_ptr2 = &(stop_watcher_2);
	this->_stop_watcher_ptr3 = &(stop_watcher_3);
	this->_dns_watcher_ptr = &(dns_watcher);
	this->_gen_task_compl_watcher_ptr = &(gen_task_compl_watcher);
	this->_file_evt_watcher_ptr = &(file_evt_watcher);


	if (this->_mode == SERVER_MODE) {
		this->_cbStruct.objPtr = this;
		this->_cbStruct.connArrived = &EVTCPServer::handleConnReq;
		socket_watcher.data = (void*)&this->_cbStruct;

		/* Making the server socket non-blocking. */
		if (!_blocking) this->socket().impl()->setBlocking(_blocking);
		/* Making the server socket non-blocking. */

		/* Async handler to wait for the command to stop the server. */
		{
			ev_io_init (&(socket_watcher), new_connection, this->sockfd(), EV_READ);
			ev_io_start (this->_loop, &(socket_watcher));
		}
	}
	else {
		this->addCLPrimaryFdToAcceptedList(_pipe_rd_fd, _pipe_wr_fd);
	}

	{
		ev_async_init (&(stop_watcher_1), stop_the_loop);
		ev_async_start (this->_loop, &(stop_watcher_1));
	}

	/* Async handler to wait for a service request from worker threads
	 * to deal with upstream connections */
	{
		/* When servicing of connected sockets is required, either to make new connection
		 * or to send data or to receive data.
		 * */
		strms_pc_cb_ptr_type pc_cb_ptr = (strms_pc_cb_ptr_type)0;;
		pc_cb_ptr = (strms_pc_cb_ptr_type)malloc(sizeof(strms_pc_cb_struct_type));
		pc_cb_ptr->objPtr = this;
		pc_cb_ptr->method = &EVTCPServer::handleServiceRequest;

		stop_watcher_2.data = (void*)pc_cb_ptr;
		ev_async_init (&(stop_watcher_2), process_service_request);
		ev_async_start (this->_loop, &(stop_watcher_2));
	}

	/* Async request to handle events occeuring from worker thread on the 
	 * accepted socket.
	 * */
	{
		/* When request processing either completes or more data is required
		 * for processing. */
		strms_pc_cb_ptr_type pc_cb_ptr = (strms_pc_cb_ptr_type)0;;
		pc_cb_ptr = (strms_pc_cb_ptr_type)malloc(sizeof(strms_pc_cb_struct_type));
		pc_cb_ptr->objPtr = this;
		pc_cb_ptr->method = &EVTCPServer::somethingHappenedInAnotherThread;

		stop_watcher_3.data = (void*)pc_cb_ptr;
		ev_async_init (&(stop_watcher_3), event_notification_on_downstream_socket);
		ev_async_start (this->_loop, &(stop_watcher_3));
	}

	{
		/* When host resolution service request completes in an auxillary thread
		 * the main event loop needs to be woken up for continuing the task.
		 * */
		strms_pc_cb_ptr_type cb_ptr = 0;
		cb_ptr = (strms_pc_cb_ptr_type) malloc(sizeof(strms_pc_cb_struct_type));
		memset(cb_ptr,0,sizeof(strms_pc_cb_struct_type));

		cb_ptr->objPtr = this;
		cb_ptr->method = &EVTCPServer::handleHostResolved;
		dns_watcher.data = (void*)cb_ptr;

		ev_async_init(&dns_watcher, host_addr_resolved);
		ev_async_start (this->_loop, &dns_watcher);
	}

	{
		/* When execution of generic task completes in an auxillary thread
		 * the main event loop needs to be woken up for continuing the task.
		 * */
		strms_pc_cb_ptr_type cb_ptr = 0;
		cb_ptr = (strms_pc_cb_ptr_type) malloc(sizeof(strms_pc_cb_struct_type));
		memset(cb_ptr,0,sizeof(strms_pc_cb_struct_type));

		cb_ptr->objPtr = this;
		cb_ptr->method = &EVTCPServer::handleGenericTaskComplete;
		gen_task_compl_watcher.data = (void*)cb_ptr;

		ev_async_init(&gen_task_compl_watcher, generic_task_complete);
		ev_async_start (this->_loop, &gen_task_compl_watcher);
	}

	{
		/* When read/close of a file completes in an auxillary thread
		 * the main event loop needs to be woken up for continuing the task.
		 * */
		strms_pc_cb_ptr_type cb_ptr = 0;
		cb_ptr = (strms_pc_cb_ptr_type) malloc(sizeof(strms_pc_cb_struct_type));
		memset(cb_ptr,0,sizeof(strms_pc_cb_struct_type));

		cb_ptr->objPtr = this;
		cb_ptr->method = &EVTCPServer::handleFileEvtOccured;
		file_evt_watcher.data = (void*)cb_ptr;

		ev_async_init(&file_evt_watcher, file_evt_occured);
		ev_async_start (this->_loop, &file_evt_watcher);
	}

	{
		/* When a time interval of normal operation completes, housekeeping
		 * tasks have to be initiated to carryout cleanups wherever necessary.
		 * */
		strms_pc_cb_ptr_type pc_cb_ptr = (strms_pc_cb_ptr_type)0;;
		pc_cb_ptr = (strms_pc_cb_ptr_type)malloc(sizeof(strms_pc_cb_struct_type));
		pc_cb_ptr->objPtr = this;
		pc_cb_ptr->method = &EVTCPServer::handlePeriodicWakeup;

		timeout_watcher.data = (void*)pc_cb_ptr;
		timeout = 5.0;
		ev_timer_init(&timeout_watcher, periodic_call_for_housekeeping, timeout, timeout);
		ev_timer_start(this->_loop, &timeout_watcher);
	}

	// now wait for events to arrive
	errno = 0;
	ev_set_syserr_cb(fatal_error);
	_loop_active = true;
	atomic_thread_fence(std::memory_order_release);
	ev_run (this->_loop, 0);

	free(stop_watcher_2.data);
	free(stop_watcher_3.data);
	free(dns_watcher.data);
	free(gen_task_compl_watcher.data);
	free(file_evt_watcher.data);
	free(timeout_watcher.data);

	{
		EVAcceptedStreamSocket *tn = _ssLRUList.getFirst();
		while (tn) {
			clearAcceptedSocket(tn->getSockfd());
			tn = _ssLRUList.getFirst();
		}
	}

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

std::string EVTCPServer::threadName(int pipe_rd_fd)
{
	char str[128];
	sprintf(str, "%d", pipe_rd_fd);
	std::string name("EVTCPServer: ");
	name = name + "Listening on:" + str;
	return name;
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

int EVTCPServer::recvDataOnConnSocket(EVTCPServiceRequest * sr)
{
	int ret = 0;
	ev_io * socket_watcher_ptr = 0;
	strms_io_cb_ptr_type cb_ptr = 0;
	int optval = 0;
	unsigned int optlen = sizeof(optval);

	EVAcceptedStreamSocket *tn = getTn(sr->accSockfd());
	errno = 0;
	if (tn->getProcState()) {

		EVConnectedStreamSocket * cn = tn->getProcState()->getEVConnSock(sr->sockfd());
		if (cn) {
			socket_watcher_ptr = cn->getSocketWatcher();
			cb_ptr = (strms_io_cb_ptr_type)socket_watcher_ptr->data;
			ev_io_stop (this->_loop, socket_watcher_ptr);
		}
		else {
			/*
			 * ERROR CONDITION:
			 * DID NOT FIND CONNECTED SOCKET FOR THE GIVEN NUMBER.
			 */
			EVEventNotification * usN = 0;
			if ((tn->getProcState()) && tn->srInSession(cb_ptr->sr_num)) {
				usN = new EVEventNotification(sr->getSRNum(), (sr->getStreamSocket().impl()->sockfd()), 
														sr->getCBEVIDNum(), -1, EBADF);
				enqueue(tn->getIoEventQueue(), (void*)usN);
				tn->newdecrNumCSEvents();
				if (!(tn->sockBusy())) {
					srCompleteEnqueue(tn);
				}
				else {
					tn->setWaitingTobeEnqueued(true);
				}
			}
			else {
				DEBUGPOINT("IS THIS AN IMPOSSIBLE CONDITION for %d\n", tn->getSockfd());
				std::abort();
			}
			return -1;
		}

		socket_watcher_ptr = cn->getSocketWatcher();
		cn->setTimeOfLastUse();

		if ((cn->getState() == EVConnectedStreamSocket::NOT_WAITING) ||
			 cn->getState() == EVConnectedStreamSocket::WAITING_FOR_WRITE) {
			int events = 0;
			if (cn->getState() == EVConnectedStreamSocket::WAITING_FOR_WRITE) {
				events = EVConnectedStreamSocket::WAITING_FOR_READWRITE;
				cn->setState(EVConnectedStreamSocket::WAITING_FOR_READWRITE);
			}
			else {
				events = EVConnectedStreamSocket::WAITING_FOR_READ;
				cn->setState(EVConnectedStreamSocket::WAITING_FOR_READ);
			}
			cb_ptr->sr_num = sr->getSRNum();
			cb_ptr->cb_evid_num = sr->getCBEVIDNum();

			/* This will invoke the call back EVTCPServer::handleConnSocketReadable. */
			ev_io_stop(this->_loop, socket_watcher_ptr);
			ev_io_init(socket_watcher_ptr, async_stream_socket_cb_3, cn->getSockfd(), events);
			ev_io_start (this->_loop, socket_watcher_ptr);
			//tn->incrNumCSEvents();
		}
	}
	// TBD TO ADD SOCKET TO TIME OUT MONITORING LIST

	return ret;
}

int EVTCPServer::pollSocketForReadOrWrite(EVTCPServiceRequest * sr)
{
	//DEBUGPOINT("EVTCPServer::pollSocketForReadOrWrite\n");
	int ret = -1;
	ev_io * socket_watcher_ptr = 0;
	strms_io_cb_ptr_type cb_ptr = 0;
	int optval = 0;
	unsigned int optlen = sizeof(optval);
	EVAcceptedStreamSocket *tn = getTn(sr->accSockfd());

	if ((tn->getProcState()) && tn->srInSession(sr->getSRNum())) {
		socket_watcher_ptr = (ev_io*)malloc(sizeof(ev_io));
		memset(socket_watcher_ptr,0,sizeof(ev_io));

		EVConnectedStreamSocket * connectedSock = new EVConnectedStreamSocket(sr->accSockfd(), sr->getStreamSocket());
		// Since this method is for making connection to a given socket address
		// There is no need for the address resolution step.
		connectedSock->setState(EVConnectedStreamSocket::BEFORE_CONNECT);
		connectedSock->setSocketWatcher(socket_watcher_ptr);
		connectedSock->setEventLoop(this->_loop);

		tn->getProcState()->setEVConnSock(connectedSock);
		connectedSock->setTimeOfLastUse();

		cb_ptr = (strms_io_cb_ptr_type) malloc(sizeof(strms_io_cb_struct_type));
		memset(cb_ptr,0,sizeof(strms_io_cb_struct_type));

		cb_ptr->objPtr = this;
		cb_ptr->sr_num = sr->getSRNum();
		cb_ptr->cb_evid_num = sr->getCBEVIDNum();
		cb_ptr->connSocketReadable = &EVTCPServer::handleConnSocketReadReady;
		cb_ptr->connSocketWritable = &EVTCPServer::handleConnSocketWriteReady;
		cb_ptr->connSocketReadAndWritable = &EVTCPServer::handleConnSocketReadAndWriteReady;
		cb_ptr->cn = connectedSock;
		cb_ptr->connSocketManaged = sr->getConnSocketManaged();
		socket_watcher_ptr->data = (void*)cb_ptr;

		int waitfor = 0;
		switch (sr->getPollFor()) {
			case EVTCPServiceRequest::READ:
				waitfor = EV_READ;
				break;
			case EVTCPServiceRequest::WRITE:
				waitfor = EV_WRITE;
				break;
			case EVTCPServiceRequest::READWRITE:
			default:
				waitfor = EV_WRITE|EV_READ;
		}
		ev_io_init(socket_watcher_ptr, async_stream_socket_cb_3, sr->getStreamSocket().impl()->sockfd(), waitfor);
		ev_io_start (this->_loop, socket_watcher_ptr);
		//tn->incrNumCSEvents();

		ret = 0;
	}

	return ret;
}

int EVTCPServer::sendDataOnConnSocket(EVTCPServiceRequest * sr)
{
	int ret = 0;
	ev_io * socket_watcher_ptr = 0;
	strms_io_cb_ptr_type cb_ptr = 0;
	int optval = 0;
	unsigned int optlen = sizeof(optval);

	EVAcceptedStreamSocket *tn = getTn(sr->accSockfd());
	errno = 0;
	if (tn->getProcState()) {

		EVConnectedStreamSocket * cn = tn->getProcState()->getEVConnSock(sr->sockfd());
		if (cn) {
			socket_watcher_ptr = cn->getSocketWatcher();
			cb_ptr = (strms_io_cb_ptr_type)socket_watcher_ptr->data;
			ev_io_stop (this->_loop, socket_watcher_ptr);
		}
		else {
			DEBUGPOINT("THIS CONDITION MUST NEVER HAPPEN SOCK = [%d]\n", tn->getSockfd());
			std::abort();
			return -1;
		}

		socket_watcher_ptr = cn->getSocketWatcher();
		cn->setTimeOfLastUse();

		srComplete(tn);
		if ((cn->getState() == EVConnectedStreamSocket::NOT_WAITING) ||
			 cn->getState() == EVConnectedStreamSocket::WAITING_FOR_READ) {
			int events = 0;
			if (cn->getState() == EVConnectedStreamSocket::WAITING_FOR_READ) {
				events = EVConnectedStreamSocket::WAITING_FOR_READWRITE;
				cn->setState(EVConnectedStreamSocket::WAITING_FOR_READWRITE);
			}
			else {
				events = EVConnectedStreamSocket::WAITING_FOR_WRITE;
				cn->setState(EVConnectedStreamSocket::WAITING_FOR_WRITE);
			}

			/* Connected socket writable does not invoke any call back.
			 * Hence there is no service request number or event number relevant for this
			 * */
			/* This will invoke the call back EVTCPServer::handleConnSocketWriteable. */
			ev_io_stop(this->_loop, socket_watcher_ptr);
			ev_io_init(socket_watcher_ptr, async_stream_socket_cb_3, cn->getSockfd(), events);
			ev_io_start (this->_loop, socket_watcher_ptr);
			//tn->incrNumCSEvents();
		}
	}

	return ret;
}

void host_resolution(void * ptr)
{
	cb_ref_data_ptr_type ref_data = 0;
	dns_io_ptr_type dio_ptr = (dns_io_ptr_type)ptr; 

	errno = 0;
	dio_ptr->_out._return_value = getaddrinfo(dio_ptr->_in._host_name,
								dio_ptr->_in._serv_name, &dio_ptr->_in._hints, &dio_ptr->_out._result);
	/*
	DEBUGPOINT("ret = [%d]\n", dio_ptr->_out._return_value);
	DEBUGPOINT("hn = [%s]\n", dio_ptr->_in._host_name);
	DEBUGPOINT("sn = [%p]\n", dio_ptr->_in._serv_name);
	DEBUGPOINT("errno = [%d]\n", errno);
	DEBUGPOINT("error = [%s]\n", strerror(errno));
	*/
	dio_ptr->_out._errno = errno;

	ref_data = (cb_ref_data_ptr_type)dio_ptr->_in._ref_data;
	ref_data->_instance->postHostResolution(dio_ptr);
	return;
}

/* This method will execute in one of the aux worker threads. */
void EVTCPServer::postHostResolution(dns_io_ptr_type dio_ptr)
{
	/* This is to make sure that multiple parallel resolution objects
	 * queue, so that the single event loop thread can handle them one by one.
	 * */
	enqueue(_host_resolve_queue, dio_ptr);
	/* Wake the event loop. */
	/* This will invoke host_addr_resolved and therefore EVTCPServer::handleHostResolved */
	ev_async_send(this->_loop, this->_dns_watcher_ptr);
}

/* Fill in code for this method to pickup the usN object and push a callback event in. */
/* This method will execute in the event loop thread. */
void EVTCPServer::handleHostResolved(const bool& ev_occured)
{
	void* pNf = 0;
	for  (pNf = dequeue(_host_resolve_queue); pNf ; pNf = dequeue(_host_resolve_queue)) {
		dns_io_ptr_type dio_ptr = ((dns_io_ptr_type)(pNf));
		cb_ref_data_ptr_type ref_data = 0;

		ref_data = (cb_ref_data_ptr_type)dio_ptr->_in._ref_data;
		EVAcceptedStreamSocket *tn = getTn(ref_data->_acc_fd);

		EVEventNotification * usN = ref_data->_usN;;
		dio_ptr->_in._ref_data = NULL;

		usN->setHRRet(dio_ptr->_out._return_value);
		usN->setRet(dio_ptr->_out._return_value);
		usN->setErrNo(dio_ptr->_out._errno);
		usN->setAddrInfo(dio_ptr->_out._result);

		//tn->decrNumCSEvents();

		if ((tn->getProcState()) && tn->srInSession(usN->getSRNum())) {
			enqueue(tn->getIoEventQueue(), (void*)usN);
			tn->newdecrNumCSEvents();
			if (!(tn->sockBusy())) {
				srCompleteEnqueue(tn);
			}
			else {
				tn->setWaitingTobeEnqueued(true);
			}
		}
		else {
			delete usN;
			DEBUGPOINT("IS THIS AN IMPOSSIBLE CONDITION for %d\n", tn->getSockfd());
			std::abort();
		}

		delete ref_data;
		delete dio_ptr;
	}
}

/* Fill in code for this method to trigger a getaddrinfo asynchronously */
int EVTCPServer::resolveHost(EVTCPServiceRequest * sr)
{
	dns_io_ptr_type dio_ptr = new dns_io_struct_type();
	EVAcceptedStreamSocket *tn = getTn(sr->accSockfd());


	dio_ptr->_in._host_name = sr->getDomainName();
	dio_ptr->_in._serv_name = sr->getServName();

	//DEBUGPOINT("Here ipv6 = %d\n", _use_ipv6_for_conn);
	if (_use_ipv6_for_conn)
		dio_ptr->_in._hints.ai_family = PF_UNSPEC;
	else
		dio_ptr->_in._hints.ai_family = PF_INET;

	dio_ptr->_in._hints.ai_socktype = SOCK_STREAM;
	dio_ptr->_in._hints.ai_protocol = IPPROTO_TCP;
	dio_ptr->_in._hints.ai_flags = AI_DEFAULT;
	//dio_ptr->_in._hints.ai_flags = AI_ALL|AI_V4MAPPED;
	//dio_ptr->_in._hints.ai_flags = AI_ALL;

	cb_ref_data_ptr_type ref_data  = new cb_ref_data_type();
	ref_data->_usN = new EVEventNotification(sr->getSRNum(), sr->getCBEVIDNum());
	ref_data->_instance = this;
	ref_data->_acc_fd = sr->accSockfd();
	dio_ptr->_in._ref_data = ref_data;

	enqueue_task(_thread_pool, &(host_resolution), dio_ptr);

	//tn->incrNumCSEvents();

	return 0;
}

/* Fill in code for this method to trigger a getaddrinfo asynchronously */
int EVTCPServer::resolveHost(EVAcceptedStreamSocket* tn, EVTCPServiceRequest* sr)
{
	dns_io_ptr_type dio_ptr = new dns_io_struct_type();

	dio_ptr->_in._host_name = sr->getDomainName();
	dio_ptr->_in._serv_name = sr->getServName();

	//DEBUGPOINT("Here ipv6 = %d\n", _use_ipv6_for_conn);
	if (_use_ipv6_for_conn)
		dio_ptr->_in._hints.ai_family = PF_UNSPEC;
	else
		dio_ptr->_in._hints.ai_family = PF_INET;

	dio_ptr->_in._hints.ai_socktype = SOCK_STREAM;
	dio_ptr->_in._hints.ai_protocol = IPPROTO_TCP;
	dio_ptr->_in._hints.ai_flags = AI_DEFAULT;
	//dio_ptr->_in._hints.ai_flags = AI_ALL|AI_V4MAPPED;
	//dio_ptr->_in._hints.ai_flags = AI_ALL;

	cb_ref_data_ptr_type ref_data  = new cb_ref_data_type();
	ref_data->_usN = new EVEventNotification(sr->getSRNum(), sr->getCBEVIDNum());
	ref_data->_instance = this;
	ref_data->_acc_fd = sr->accSockfd();
	dio_ptr->_in._ref_data = ref_data;

	enqueue_task(_thread_pool, &(host_resolution), dio_ptr);

	//tn->incrNumCSEvents();

	return 0;
}

typedef struct {
	int _fd;
	int _completed_oper;
} file_evt_s, * file_evt_p;

void EVTCPServer::handleFileEvtOccured(const bool& ev_occured)
{
	void* pNf = 0;
	for  (pNf = dequeue(_file_evt_queue); pNf ; pNf = dequeue(_file_evt_queue)) {
		file_evt_p fe_ptr = ((file_evt_p)(pNf));

		try {
			file_event_status_s& fes = _file_evt_subscriptions.at(fe_ptr->_fd);
			EVAcceptedStreamSocket *tn = getTn(fes._acc_fd);

			if (!tn) {
				DEBUGPOINT("Here tn has become null while task was being processed\n");
				return;
			}
			EVEventNotification * usN = fes._usN;;
			if (fe_ptr->_completed_oper == FILE_OPER_OPEN) {
				errno = 0;
				int status = ef_open_status(fe_ptr->_fd);
				usN->setErrNo(errno);
				usN->setRet(status);
			}
			else if (fe_ptr->_completed_oper == FILE_OPER_READ) {
				int status = ef_file_ready_for_read(fe_ptr->_fd);
				//DEBUGPOINT("Here ret = %d errno = %d\n", status, errno);
				usN->setErrNo(errno);
				usN->setRet(status);
			}
			else {
				DEBUGPOINT("THIS MUST NOT HAPPEN\n");
				std::abort();
			}

			//DEBUGPOINT("Here fd = %d oper = %d\n", fe_ptr->_fd, fe_ptr->_completed_oper);
			usN->setFileFd(fe_ptr->_fd);
			usN->setFileOper(fe_ptr->_completed_oper);

			if ((tn->getProcState()) && tn->srInSession(usN->getSRNum())) {
				enqueue(tn->getIoEventQueue(), (void*)usN);
				tn->newdecrNumCSEvents();
				if (!(tn->sockBusy())) {
					srCompleteEnqueue(tn);
				}
				else {
					tn->setWaitingTobeEnqueued(true);
				}
			}
			else {
				delete usN;
				DEBUGPOINT("IS THIS AN IMPOSSIBLE CONDITION for %d\n", tn->getSockfd());
				std::abort();
			}

			//tn->decrNumCSEvents();
			_file_evt_subscriptions.erase(fe_ptr->_fd);
			(tn->getProcState()->getFileEvtSubscriptions()).erase(fe_ptr->_fd);
		}
		catch (...) {
			/* No subcriptions for events of this file. */
		}
		delete fe_ptr;
	}
}

void EVTCPServer::pushFileEvent(int fd, int completed_oper)
{
	//DEBUGPOINT("Here\n");
	file_evt_p fe_ptr = (file_evt_p)malloc(sizeof(file_evt_s));
	/* This is to make sure that multiple parallel file event completions
	 * queue up, so that the single event loop thread can handle them one by one.
	 * */
	fe_ptr->_fd = fd;
	fe_ptr->_completed_oper = completed_oper;

	enqueue(_file_evt_queue, fe_ptr);

	/* Wake the event loop. */
	/* This will invoke file_evt_occured and therefore EVTCPServer::handleFileEvtOccured */
	ev_spin_lock(this->_loop_active_spin_lock);
	atomic_thread_fence(std::memory_order_acquire);
	if (_loop_active) ev_async_send(this->_loop, this->_file_evt_watcher_ptr);
	ev_spin_unlock(this->_loop_active_spin_lock);

}

typedef struct {
	poco_socket_t _acc_fd;
	EVEventNotification* _usN;
} tc_enqueued_struct, * tc_enqueued_struct_ptr;

/* This is handling of task completion within the event loop.
 * So that the event of task completion can be sent to the 
 * correct worker thread handling the request.
 * */
void EVTCPServer::handleGenericTaskComplete(const bool& ev_occured)
{
	//DEBUGPOINT("Here\n");
	void* pNf = 0;
	for  (pNf = dequeue(_aux_tc_queue); pNf ; pNf = dequeue(_aux_tc_queue)) {
		tc_enqueued_struct_ptr tc_ptr = ((tc_enqueued_struct_ptr)(pNf));

		EVAcceptedStreamSocket *tn = getTn(tc_ptr->_acc_fd);
		if (!tn) {
			DEBUGPOINT("Here tn has become null while task was being processed\n");
			delete tc_ptr;
			return;
		}
		EVEventNotification * usN = tc_ptr->_usN;;

		if ((tn->getProcState()) && tn->srInSession(usN->getSRNum())) {
			enqueue(tn->getIoEventQueue(), (void*)usN);
			tn->newdecrNumCSEvents();
			if (!(tn->sockBusy())) {
				srCompleteEnqueue(tn);
			}
			else {
				tn->setWaitingTobeEnqueued(true);
			}
		}
		else {
			delete usN;
			if (usN->getTaskReturnValue()) { free(usN->getTaskReturnValue()); usN->setTaskReturnValue(NULL); }
			DEBUGPOINT("REACHED HERE, WHICH MUST NEVER HAVE HAPPENED\n");
			std::abort();
		}

		//tn->decrNumCSEvents();
		delete tc_ptr;
	}
	//DEBUGPOINT("Here\n");
}

void EVTCPServer::postGenericTaskComplete(poco_socket_t acc_fd, EVEventNotification *usN)
{
	//DEBUGPOINT("Here\n");
	tc_enqueued_struct_ptr tc_ptr = (tc_enqueued_struct_ptr)malloc(sizeof(tc_enqueued_struct));
	/* This is to make sure that multiple parallel task completion objects
	 * queue up, so that the single event loop thread can handle them one by one.
	 * */
	tc_ptr->_acc_fd = acc_fd;
	tc_ptr->_usN = usN;
	//DEBUGPOINT("Here %p\n", tc_ptr->_usN);
	//tc_ptr->_usN->debug(__FILE__, __LINE__);
	enqueue(_aux_tc_queue, tc_ptr);
	/* Wake the event loop. */
	/* This will invoke generic_task_complete and therefore EVTCPServer::handleGenericTaskComplete */
	ev_async_send(this->_loop, this->_gen_task_compl_watcher_ptr);
	//DEBUGPOINT("Here\n");
}

static void post_task_completion(void* return_data, void* ref_data)
{
	cb_ref_data_ptr_type ref = (cb_ref_data_ptr_type)ref_data;
	if (ref) {
		ref->_usN->setTaskReturnValue(return_data);
		ref->_usN->setRet(0);
		ref->_instance->postGenericTaskComplete(ref->_acc_fd, ref->_usN);
	}
	else {
		/*
		 * If the task completion is not waited for
		 * the return data from the task should be NULL.
		 * */
		poco_assert (return_data == NULL);
	}
	delete ref;
	return;
}

/* Fill in code for this method to trigger a getaddrinfo asynchronously */
int EVTCPServer::initiateGenericTask(EVTCPServiceRequest * sr)
{
	void* task_input_data = sr->getTaskInputData();
	EVAcceptedStreamSocket *tn = getTn(sr->accSockfd());

	cb_ref_data_ptr_type ref_data  = new cb_ref_data_type();

	ref_data->_usN = new EVEventNotification(sr->getSRNum(), sr->getCBEVIDNum());
	ref_data->_instance = this;
	ref_data->_acc_fd = sr->accSockfd();

	enqueue_task_function(_thread_pool, (sr->getTaskFunc()), task_input_data, ref_data, &post_task_completion);

	//tn->incrNumCSEvents();

	//DEBUGPOINT("Here func = %p, notification_func = %p, inp = %p %s\n", sr->getTaskFunc(), &post_task_completion, task_input_data, (char*)task_input_data);
	//DEBUGPOINT("Here\n");
	return 0;
}

int EVTCPServer::initiateGenericTask(EVAcceptedStreamSocket * tn, EVTCPServiceRequest * sr)
{
	void* task_input_data = sr->getTaskInputData();

	cb_ref_data_ptr_type ref_data  = new cb_ref_data_type();

	ref_data->_usN = new EVEventNotification(sr->getSRNum(), sr->getCBEVIDNum());
	ref_data->_instance = this;
	ref_data->_acc_fd = sr->accSockfd();

	enqueue_task_function(_thread_pool, (sr->getTaskFunc()), task_input_data, ref_data, &post_task_completion);

	//tn->incrNumCSEvents();

	//DEBUGPOINT("Here func = %p, notification_func = %p, inp = %p %s\n", sr->getTaskFunc(), &post_task_completion, task_input_data, (char*)task_input_data);
	//DEBUGPOINT("Here\n");
	return 0;
}

int EVTCPServer::initiateGenericTaskNR(EVTCPServiceRequest * sr)
{
	void* task_input_data = sr->getTaskInputData();

	enqueue_task_function(_thread_pool, (sr->getTaskFunc()), task_input_data, NULL, &post_task_completion);

	return 0;
}

int EVTCPServer::makeTCPConnection(EVTCPServiceRequest * sr)
{
	int ret = 0;
	ev_io * socket_watcher_ptr = 0;
	strms_io_cb_ptr_type cb_ptr = 0;
	int optval = 0;
	unsigned int optlen = sizeof(optval);

	EVAcceptedStreamSocket *tn = getTn(sr->accSockfd());
	errno = 0;
	try {
		sr->getStreamSocket().connectNB(sr->getAddr());
	} catch (Exception &e) {
		DEBUGPOINT("Exception = %s\n", e.what());
		optval = errno;
		ret = -1;
	}


	if (ret < 0) {
		DEBUGPOINT("Here from %d\n", tn->getSockfd());

		// SO_ERROR probably works only in case of select system call.
		// It is not returning the correct errno over here.
		//getsockopt(sr->getStreamSocket().impl()->sockfd(), SOL_SOCKET, SO_ERROR, (void*)&optval, &optlen);

		/* Enqueue the notification only if the accepted socket is still being processed.
		 * 
		 * For consideration
		 * TBD: We may have to further make sure that the service request for which this notification
		 * is being passed is in the same session as the current state.
		 * */
		if ((tn->getProcState()) && tn->srInSession(sr->getSRNum())) {
			EVEventNotification * usN = 0;
			usN = new EVEventNotification(sr->getSRNum(), (sr->getStreamSocket().impl()->sockfd()), 
													sr->getCBEVIDNum(), ret, optval);
			enqueue(tn->getIoEventQueue(), (void*)usN);
			tn->newdecrNumCSEvents();
			if (!(tn->sockBusy())) {
				srCompleteEnqueue(tn);
			}
			else {
				tn->setWaitingTobeEnqueued(true);
			}
		}
		else {
			DEBUGPOINT("IS THIS AN IMPOSSIBLE CONDITION for %d\n", tn->getSockfd());
			std::abort();
		}
		return ret;
	}

	socket_watcher_ptr = (ev_io*)malloc(sizeof(ev_io));
	memset(socket_watcher_ptr,0,sizeof(ev_io));

	EVConnectedStreamSocket * connectedSock = new EVConnectedStreamSocket(sr->accSockfd(), sr->getStreamSocket());
	// Since this method is for making connection to a given socket address
	// There is no need for the address resolution step.
	connectedSock->setState(EVConnectedStreamSocket::BEFORE_CONNECT);
	connectedSock->setSocketWatcher(socket_watcher_ptr);
	connectedSock->setEventLoop(this->_loop);

	tn->getProcState()->setEVConnSock(connectedSock);
	connectedSock->setTimeOfLastUse();

	cb_ptr = (strms_io_cb_ptr_type) malloc(sizeof(strms_io_cb_struct_type));
	memset(cb_ptr,0,sizeof(strms_io_cb_struct_type));

	cb_ptr->objPtr = this;
	cb_ptr->sr_num = sr->getSRNum();
	cb_ptr->cb_evid_num = sr->getCBEVIDNum();
	cb_ptr->connSocketReadable = &EVTCPServer::handleConnSocketReadable;
	cb_ptr->connSocketWritable = &EVTCPServer::handleConnSocketWriteable;
	cb_ptr->cn = connectedSock;
	socket_watcher_ptr->data = (void*)cb_ptr;

	ev_io_init(socket_watcher_ptr, async_stream_socket_cb_3, sr->getStreamSocket().impl()->sockfd(), EV_WRITE);
	ev_io_start (this->_loop, socket_watcher_ptr);
	//tn->incrNumCSEvents();

	return ret;
}

int EVTCPServer::closeTCPConnection(EVTCPServiceRequest * sr)
{
	int ret = 0;
	ev_io * socket_watcher_ptr = 0;
	strms_io_cb_ptr_type cb_ptr = 0;

	EVAcceptedStreamSocket *tn = getTn(sr->accSockfd());
	if (tn->getProcState()) {
		EVConnectedStreamSocket * cn = tn->getProcState()->getEVConnSock(sr->sockfd());
		if (cn) {
			socket_watcher_ptr = cn->getSocketWatcher();
			ev_io_stop (this->_loop, socket_watcher_ptr); }

		errno = 0;
		ret = 0;
		try {
			sr->getStreamSocket().close();
		} catch (Exception &e) {
			ret = -1;
		}

		tn->getProcState()->eraseEVConnSock(sr->accSockfd());
	}

	/* We do not enqueue upstream notification for socket closure.
	 * Neither do we check for accepted socket being busy etc.
	 *
	 * The assumption is that the caller is not really interested in
	 * result of the closure operation.
	 * */

	int fd = sr->getStreamSocket().impl()->sockfd();
	return ret;
}

int EVTCPServer::pollFileOpenEvent(EVTCPServiceRequest * sr)
{
	EVAcceptedStreamSocket *tn = getTn(sr->accSockfd());
	errno = 0;
	if ((tn->getProcState()) && tn->srInSession(sr->getSRNum())) {
		//DEBUGPOINT("Here\n");
		EVEventNotification * usN = 0;
		usN = new EVEventNotification(sr->getSRNum(), sr->getCBEVIDNum());
		usN->setFileFd(sr->getFileFd());
		usN->setFileOper(FILE_OPER_OPEN);

		FileEvtSubscrMap::iterator it = _file_evt_subscriptions.find(sr->getFileFd());
		if (_file_evt_subscriptions.end() != it) {
		//DEBUGPOINT("Here\n");
			usN->setErrNo(EBUSY);
			usN->setRet(-1);

			enqueue(tn->getIoEventQueue(), (void*)usN);
			tn->newdecrNumCSEvents();
			if (!(tn->sockBusy())) {
				srCompleteEnqueue(tn);
			}
			else {
				tn->setWaitingTobeEnqueued(true);
			}
		}
		else {

			int ret = ef_open_status(sr->getFileFd());
			if (ret == -1) {
			//DEBUGPOINT("Here\n");
				if (errno == EAGAIN) {
			//DEBUGPOINT("Here %d\n", ret);
					file_event_status_s fes;
					fes._usN = usN;
					fes._acc_fd = sr->accSockfd();
					_file_evt_subscriptions[sr->getFileFd()] = fes;
					(tn->getProcState()->getFileEvtSubscriptions())[sr->getFileFd()] = sr->getFileFd();
					//tn->incrNumCSEvents();
				}
				else {
			//DEBUGPOINT("Here %d\n", ret);
					usN->setErrNo(errno);
					usN->setRet(ret);

					enqueue(tn->getIoEventQueue(), (void*)usN);
					tn->newdecrNumCSEvents();
					if (!(tn->sockBusy())) {
						srCompleteEnqueue(tn);
					}
					else {
						tn->setWaitingTobeEnqueued(true);
					}
				}
			}
			else {
			//DEBUGPOINT("Here %d errno %d\n", ret, errno);
				usN->setErrNo(0);
				usN->setRet(ret);
				usN->setFileFd(sr->getFileFd());

				enqueue(tn->getIoEventQueue(), (void*)usN);
				tn->newdecrNumCSEvents();
				if (!(tn->sockBusy())) {
					srCompleteEnqueue(tn);
				}
				else {
					tn->setWaitingTobeEnqueued(true);
				}
			}
		}
	}

	return 0;
}

int EVTCPServer::pollFileReadEvent(EVTCPServiceRequest * sr)
{
	EVAcceptedStreamSocket *tn = getTn(sr->accSockfd());

	if ((tn->getProcState()) && tn->srInSession(sr->getSRNum())) {
		//DEBUGPOINT("Here\n");

		EVEventNotification * usN = 0;
		usN = new EVEventNotification(sr->getSRNum(), sr->getCBEVIDNum());
		usN->setFileFd(sr->getFileFd());
		usN->setFileOper(FILE_OPER_READ);

		FileEvtSubscrMap::iterator it = _file_evt_subscriptions.find(sr->getFileFd());
		if (_file_evt_subscriptions.end() != it) {
			//DEBUGPOINT("Here\n");
			usN->setErrNo(EBUSY);
			usN->setRet(-1);

			enqueue(tn->getIoEventQueue(), (void*)usN);
			tn->newdecrNumCSEvents();
			if (!(tn->sockBusy())) {
				srCompleteEnqueue(tn);
			}
			else {
				tn->setWaitingTobeEnqueued(true);
			}
		}
		else {

			errno = 0;
			int ret = ef_file_ready_for_read(sr->getFileFd());
			if (ret < 0) {
				//DEBUGPOINT("Here ret = %d errno = %d\n", ret, errno);
				if (errno == EAGAIN) {
					//DEBUGPOINT("Here ret = %d errno = %d\n", ret, errno);
					file_event_status_s fes;
					fes._usN = usN;
					fes._acc_fd = sr->accSockfd();
					_file_evt_subscriptions[sr->getFileFd()] = fes;
					(tn->getProcState()->getFileEvtSubscriptions())[sr->getFileFd()] = sr->getFileFd();
					//tn->incrNumCSEvents();
				}
				else {
					//DEBUGPOINT("Here ret = %d errno = %d\n", ret, errno);
					usN->setErrNo(errno);
					usN->setRet(ret);

					enqueue(tn->getIoEventQueue(), (void*)usN);
					tn->newdecrNumCSEvents();
					if (!(tn->sockBusy())) {
						srCompleteEnqueue(tn);
					}
					else {
						tn->setWaitingTobeEnqueued(true);
					}
				}
			}
			else {
				//DEBUGPOINT("Here ret = %d errno = %d\n", ret, errno);
				usN->setErrNo(0);
				usN->setRet(ret); /* >0 means data available, 0 means EOF */

				enqueue(tn->getIoEventQueue(), (void*)usN);
				tn->newdecrNumCSEvents();
				if (!(tn->sockBusy())) {
					srCompleteEnqueue(tn);
				}
				else {
					tn->setWaitingTobeEnqueued(true);
				}
			}
		}
	}

	return 0;
}

void EVTCPServer::handleServiceRequest(const bool& ev_occured)
{
	AutoPtr<Notification> pNf = 0;
	for  (pNf = _service_request_queue.dequeueNotification(); pNf ; pNf = _service_request_queue.dequeueNotification()) {
		EVTCPServiceRequest * srNF = dynamic_cast<EVTCPServiceRequest*>(pNf.get());
		EVTCPServiceRequest::what event = srNF->getEvent();
		EVAcceptedStreamSocket *tn = getTn(srNF->accSockfd());
		if (!tn) {
			/* This should never happen. */
			DEBUGPOINT("Did not find entry in _accssColl for [%d][%d] for event = [%d]\n",
													srNF->sockfd(), srNF->accSockfd(),  event);

			/* Multiple events can get queued for a socket from another thread.
			 * In the meanwhile, it is possible that the socket gets into an error state
			 * due to various conditions, one such is wrong data format and the protocol
			 * handler fails. This condition will lead to socket getting closed.
			 * Subsequent events after closing of the socket must be ignored.
			 * */

			// TBD Handle sending of error event here. TBD

			continue;
		}
		//DEBUGPOINT("newpendingCSEvents() = [%d]\n", tn->newpendingCSEvents());
		if (!(tn->getProcState()) || !(tn->srInSession(srNF->getSRNum()))) {
			DEBUGPOINT("Here DEAD REQUEST %d\n", srNF->getEvent());
			continue;
		}

		switch (event) {
			case EVTCPServiceRequest::HOST_RESOLUTION:
				//DEBUGPOINT("HOST_RESOLUTION from %d\n", tn->getSockfd());
				resolveHost(srNF);
				break;
			case EVTCPServiceRequest::POLL_REQUEST:
				//DEBUGPOINT("POLL_REQUEST from %d\n", tn->getSockfd());
				pollSocketForReadOrWrite(srNF);
				break;
			case EVTCPServiceRequest::CONNECTION_REQUEST:
				//DEBUGPOINT("CONNECTION_REQUEST from %d\n", tn->getSockfd());
				makeTCPConnection(srNF);
				break;
			case EVTCPServiceRequest::CLEANUP_REQUEST:
				//DEBUGPOINT("CLEANUP_REQUEST from %d\n", tn->getSockfd());
				closeTCPConnection(srNF);
				break;
			case EVTCPServiceRequest::SENDDATA_REQUEST:
				//DEBUGPOINT("SENDDATA_REQUEST from %d\n", tn->getSockfd());
				sendDataOnConnSocket(srNF);
				break;
			case EVTCPServiceRequest::RECVDATA_REQUEST:
				//DEBUGPOINT("RECVDATA_REQUEST from %d\n", tn->getSockfd());
				recvDataOnConnSocket(srNF);
				break;
			case EVTCPServiceRequest::GENERIC_TASK:
				//DEBUGPOINT("GENERIC_TASK from %d\n", tn->getSockfd());
				initiateGenericTask(srNF);
				break;
			case EVTCPServiceRequest::GENERIC_TASK_NR:
				//DEBUGPOINT("GENERIC_TASK_NR from %d\n", tn->getSockfd());
				initiateGenericTaskNR(srNF);
				break;
			case EVTCPServiceRequest::FILEOPEN_NOTIFICATION:
				//DEBUGPOINT("FILEOPEN_NOTIFICATION from %d\n", tn->getSockfd());
				pollFileOpenEvent(srNF);
				break;
			case EVTCPServiceRequest::FILEREAD_NOTIFICATION:
				//DEBUGPOINT("FILEREAD_NOTIFICATION from %d\n", tn->getSockfd());
				pollFileReadEvent(srNF);
				break;
			case EVTCPServiceRequest::INITIATE_REDIS_CONNECTION:
				//DEBUGPOINT("INITIATE_REDIS_CONNECTION from %d\n", tn->getSockfd());
				break;
			case EVTCPServiceRequest::TRANSCEIVE_REDIS_COMMAND:
				//DEBUGPOINT("TRANSCEIVE_REDIS_COMMAND from %d\n", tn->getSockfd());
				addRedisSocketToPoll(srNF);
				break;
			case EVTCPServiceRequest::CLOSE_REDIS_CONNECTION:
				//DEBUGPOINT("CLOSE_REDIS_CONNECTION from %d\n", tn->getSockfd());
				closeRedisConnection(srNF);
				break;
			case EVTCPServiceRequest::SEND_DATA_ON_ACC_SOCK:
				//DEBUGPOINT("SEND_DATA_ON_ACC_SOCK from %d\n", tn->getSockfd());
				sendRawDataOnAccSocketProcess(srNF);
				break;
			case EVTCPServiceRequest::TRACK_AS_WEBSOCKET:
				//DEBUGPOINT("TRACK_AS_WEBSOCKET from %d\n", tn->getSockfd());
				trackAsWebSocketProcess(srNF);
				break;
			case EVTCPServiceRequest::SET_EV_TIMER:
				//DEBUGPOINT("SET_EV_TIMER from %d\n", tn->getSockfd());
				evTimerProcess(srNF);
				break;
			case EVTCPServiceRequest::SHUTDOWN_WEBSOCKET:
				//DEBUGPOINT("SHUTDOWN_WEBSOCKET from %d\n", tn->getSockfd());
				shutdownWebSocketProcess(srNF);
				break;
			default:
				//DEBUGPOINT("INVALID EVENT %d from %d\n", event, tn->getSockfd());
				std::abort();
				break;
		}

		srNF = NULL;
	}

	return;
}

void EVTCPServer::justEnqueue(EVAcceptedStreamSocket* tn)
{
	tn->setSockBusy();
	_pDispatcher->enqueue(tn);
}

void EVTCPServer::srCompleteEnqueue(EVAcceptedStreamSocket* tn)
{
	//DEBUGPOINT("DECREMENTING FOR [%d]\n", tn->getSockfd());
	//tn->newdecrNumCSEvents();
	if (!tn->sockInError()) {
		//DEBUGPOINT("Here\n");
		tn->setSockBusy();
		_pDispatcher->enqueue(tn);
	}
	else {
		DEBUGPOINT("Here\n");
		errorInAuxProcesing(tn->getSockfd(), true);
	}
}

void EVTCPServer::srComplete(EVAcceptedStreamSocket* tn)
{
	//DEBUGPOINT("DECREMENTING FOR [%d]\n", tn->getSockfd());
	tn->newdecrNumCSEvents();
}

void EVTCPServer::enqueueSR(EVAcceptedSocket * en, EVTCPServiceRequest * sr)
{
	//DEBUGPOINT("ENQUEUEING FOR %d\n", en->getSockfd());
	en->newincrNumCSEvents();
	_service_request_queue.enqueueNotification(sr);
	return ;
}

long EVTCPServer::submitRequestForRecvData(int cb_evid_num, EVAcceptedSocket *en, Net::StreamSocket& css)
{
	long sr_num = getNextSRSrlNum();

	/* Enque the service request */
	enqueueSR(en, new EVTCPServiceRequest(sr_num, cb_evid_num,
										EVTCPServiceRequest::RECVDATA_REQUEST, en->getSockfd(), css));

	/* And then wake up the loop calls process_service_request */
	ev_async_send(this->_loop, this->_stop_watcher_ptr2);
	/* This will result in invocation of handleServiceRequest */
	return sr_num;
}

long EVTCPServer::submitRequestForSendData(EVAcceptedSocket *en, Net::StreamSocket& css)
{
	long sr_num = getNextSRSrlNum();

	/* Enque the service request */
	enqueueSR(en, new EVTCPServiceRequest(sr_num, EVTCPServiceRequest::SENDDATA_REQUEST, en->getSockfd(), css));

	/* And then wake up the loop calls process_service_request */
	ev_async_send(this->_loop, this->_stop_watcher_ptr2);
	/* This will result in invocation of handleServiceRequest */
	return sr_num;
}

long EVTCPServer::submitRequestForHostResolution(int cb_evid_num, EVAcceptedSocket *en, const char* domain_name, const char* serv_name)
{
	long sr_num = getNextSRSrlNum();

	EVTCPServiceRequest sr(sr_num, cb_evid_num,
							EVTCPServiceRequest::HOST_RESOLUTION, en->getSockfd(), domain_name, serv_name);
	en->newincrNumCSEvents();
	resolveHost((EVAcceptedStreamSocket*)en, &sr);

	return sr_num;
}

//long EVTCPServer::submitRequestForHostResolution(int cb_evid_num, EVAcceptedSocket *en, const char* domain_name, const char* serv_name)
//{
	//long sr_num = getNextSRSrlNum();

	/* Enque the service request */
	//enqueueSR(en, new EVTCPServiceRequest(sr_num, cb_evid_num,
										//EVTCPServiceRequest::HOST_RESOLUTION, en->getSockfd(), domain_name, serv_name));

	/* And then wake up the loop calls process_service_request */
	//ev_async_send(this->_loop, this->_stop_watcher_ptr2);
	/* This will result in invocation of handleServiceRequest */
	//return sr_num;
//}

long EVTCPServer::submitRequestForConnection(int cb_evid_num, EVAcceptedSocket *en, Net::SocketAddress& addr, Net::StreamSocket& css)
{
	long sr_num = getNextSRSrlNum();

	/* Enque the service request */
	enqueueSR(en, new EVTCPServiceRequest(sr_num, cb_evid_num,
										EVTCPServiceRequest::CONNECTION_REQUEST, en->getSockfd(), css, addr));

	/* And then wake up the loop calls process_service_request */
	ev_async_send(this->_loop, this->_stop_watcher_ptr2);
	/* This will result in invocation of handleServiceRequest */
	return sr_num;
}

long EVTCPServer::submitRequestForPoll(int cb_evid_num, EVAcceptedSocket *en, Net::StreamSocket& css, int poll_for, int managed)
{
	long sr_num = getNextSRSrlNum();

	/* Enque the service request */
	//DEBUGPOINT("sr_num = [%d]:[%ld][%d][%d]\n", css.impl()->sockfd(), sr_num, poll_for, managed);
	EVTCPServiceRequest *sr = new EVTCPServiceRequest(sr_num, cb_evid_num,
                                        EVTCPServiceRequest::POLL_REQUEST, en->getSockfd(), css);
	sr->setPollFor(poll_for);
	sr->setConnSocketManaged(managed);
	enqueueSR(en, sr);

	/* And then wake up the loop calls process_service_request */
	ev_async_send(this->_loop, this->_stop_watcher_ptr2);
	/* This will result in invocation of handleServiceRequest */
	return sr_num;
}

long EVTCPServer::submitRequestForClose(EVAcceptedSocket *en, Net::StreamSocket& css)
{
	long sr_num = getNextSRSrlNum();

	/* Enque the service request */
	enqueueSR(en, new EVTCPServiceRequest(sr_num, EVTCPServiceRequest::CLEANUP_REQUEST, en->getSockfd(), css));

	/* And then wake up the loop calls process_service_request */
	ev_async_send(this->_loop, this->_stop_watcher_ptr2);
	/* This will result in invocation of handleServiceRequest */
	return sr_num;
}

/* TBD
 * Consider implementing execution of generic task without waking up the event listener thread 2 times.
 * The task can be initiated in the worker thread itself and upon completion, the completion handler can
 * wake up the event listener to submit the event back to the worker thread.
 * This however can violate certain safety conditions.
 * It requires to be thoughroughly checked and designed before implementation.
 * */
long EVTCPServer::submitRequestForTaskExecution(int cb_evid_num,
							EVAcceptedSocket *en, generic_task_handler_t tf, void* input_data)
{
	long sr_num = getNextSRSrlNum();

	EVTCPServiceRequest sr(sr_num, cb_evid_num,
                            EVTCPServiceRequest::GENERIC_TASK, en->getSockfd(), tf, input_data);
	en->newincrNumCSEvents();
	initiateGenericTask((EVAcceptedStreamSocket*)en, &sr);

	return sr_num;
}

//long EVTCPServer::submitRequestForTaskExecution(int cb_evid_num,
							//EVAcceptedSocket *en, generic_task_handler_t tf, void* input_data)
//{
	//long sr_num = getNextSRSrlNum();

	/* Enque the service request */
	//DEBUGPOINT("Here loop = %p, sw = %p on socket %d\n", this->_loop, this->_stop_watcher_ptr2, en->getSockfd());
	//enqueueSR(en, new EVTCPServiceRequest(sr_num, cb_evid_num,
							//EVTCPServiceRequest::GENERIC_TASK, en->getSockfd(), tf, input_data));

	/* And then wake up the loop calls process_service_request */
	//ev_async_send(this->_loop, this->_stop_watcher_ptr2);
	/* This will result in invocation of handleServiceRequest */
	//return sr_num;
//}

long EVTCPServer::submitRequestForTaskExecutionNR(generic_task_handler_nr_t tf, void* input_data)
{
	long sr_num = getNextSRSrlNum();
	//DEBUGPOINT("Here %p\n", tf);
	//DEBUGPOINT("Here %p\n", input_data);
	enqueue_task(_thread_pool, tf, input_data);
	return sr_num;
}

long EVTCPServer::notifyOnFileOpen(int cb_evid_num, EVAcceptedSocket *en, int fd)
{
	long sr_num = getNextSRSrlNum();

	/* Enque the service request */
	enqueueSR(en, new EVTCPServiceRequest(sr_num, cb_evid_num,
									EVTCPServiceRequest::FILEOPEN_NOTIFICATION, en->getSockfd(), fd));

	/* And then wake up the loop calls process_service_request */
	ev_async_send(this->_loop, this->_stop_watcher_ptr2);
	/* This will result in invocation of handleServiceRequest */

	return sr_num;
}

long EVTCPServer::notifyOnFileRead(int cb_evid_num, EVAcceptedSocket *en, int fd)
{
	long sr_num = getNextSRSrlNum();

	/* Enque the service request */
	enqueueSR(en, new EVTCPServiceRequest(sr_num, cb_evid_num,
									EVTCPServiceRequest::FILEREAD_NOTIFICATION, en->getSockfd(), fd));

	/* And then wake up the loop calls process_service_request */
	ev_async_send(this->_loop, this->_stop_watcher_ptr2);
	/* This will result in invocation of handleServiceRequest */

	return sr_num;
}


/*
 * REDIS INTERFACE RELATED FUNCTIONS 
 */

typedef void (EVTCPServer::*transceive_complete_handler)(struct redis_call_related_data *);
struct redis_call_related_data {
	redisAsyncContext *ac;
	const char * message;
	EVTCPServer * server_ptr;
	redisReply * reply;
	long sr_num;
	int cb_evid_num;
	int acc_fd;
	transceive_complete_handler  handle_redis_transceive_complete;
};

void EVTCPServer::handle_redis_transceive_complete(struct redis_call_related_data * redis_data_ptr)
{
	EVAcceptedStreamSocket *tn = getTn(redis_data_ptr->acc_fd);
	if (!tn) {
		DEBUGPOINT("REACHED HERE, WHICH MUST NEVER HAVE HAPPENED\n");
		free(redis_data_ptr);
		std::abort();
		return;
	}
	EVEventNotification * usN =
		new EVEventNotification(redis_data_ptr->sr_num, redis_data_ptr->cb_evid_num);
	usN->setTaskReturnValue(redis_data_ptr->reply);

	if ((tn->getProcState()) && tn->srInSession(usN->getSRNum())) {
		enqueue(tn->getIoEventQueue(), (void*)usN);
		tn->newdecrNumCSEvents();
		if (!(tn->sockBusy())) {
			srCompleteEnqueue(tn);
		}
		else {
			tn->setWaitingTobeEnqueued(true);
		}
	}
	else {
		delete usN;
		free(redis_data_ptr);
		DEBUGPOINT("REACHED HERE, WHICH MUST NEVER HAVE HAPPENED\n");
		std::abort();
		return;
	}

	//tn->decrNumCSEvents();

	free(redis_data_ptr);
	return;
}

static void redis_callback(redisAsyncContext *ac, void * r, void * private_data)
{
	struct redis_call_related_data * redis_data_ptr = (struct redis_call_related_data *)private_data;

	redis_data_ptr->reply = (redisReply *)r;
	((redis_data_ptr->server_ptr)->*(redis_data_ptr->handle_redis_transceive_complete))(redis_data_ptr);

	return;
}

int EVTCPServer::addRedisSocketToPoll(EVTCPServiceRequest * sr)
{
	struct redis_call_related_data * redis_data_ptr ;
	redis_data_ptr = (struct redis_call_related_data *)sr->getTaskInputData();
	EVAcceptedStreamSocket *tn = getTn(sr->accSockfd());

	redis_data_ptr->server_ptr = this;
	redis_data_ptr->handle_redis_transceive_complete = &EVTCPServer::handle_redis_transceive_complete;
	redis_data_ptr->sr_num = sr->getSRNum();
	redis_data_ptr->cb_evid_num = sr->getCBEVIDNum();
	redis_data_ptr->acc_fd = sr->accSockfd();

	redisAsyncCommand(redis_data_ptr->ac, redis_callback, (void*)redis_data_ptr, redis_data_ptr->message);

	//tn->incrNumCSEvents();

	return 0;
}

long EVTCPServer::redistransceive(int cb_evid_num, EVAcceptedSocket *en, redisAsyncContext *ac, const char * message)
{
	long sr_num = getNextSRSrlNum();
	struct redis_call_related_data *redis_data_ptr = (struct redis_call_related_data*)malloc(sizeof(struct redis_call_related_data));
	redis_data_ptr->ac = ac;
	redis_data_ptr->message = message;
	redis_data_ptr->server_ptr = NULL;

	/* Enque the service request */
	enqueueSR(en, new EVTCPServiceRequest(sr_num, cb_evid_num,
									EVTCPServiceRequest::TRANSCEIVE_REDIS_COMMAND, en->getSockfd(), (void*)redis_data_ptr));

	/* And then wake up the loop calls process_service_request */
	ev_async_send(this->_loop, this->_stop_watcher_ptr2);
	/* This will result in invocation of handleServiceRequest
	 * and addRedisSocketToPoll */


	return sr_num;
}

int EVTCPServer::closeRedisConnection(EVTCPServiceRequest * sr)
{
	struct redis_call_related_data * redis_data_ptr ;
	redis_data_ptr = (struct redis_call_related_data *)sr->getTaskInputData();
	EVAcceptedStreamSocket *tn = getTn(sr->accSockfd());

	redisAsyncDisconnect(redis_data_ptr->ac);

	free(redis_data_ptr);
	tn->newdecrNumCSEvents();

	return 0;
}

long EVTCPServer::redisDisconnect(int cb_evid_num, EVAcceptedSocket *en, redisAsyncContext *ac)
{
	long sr_num = getNextSRSrlNum();
	struct redis_call_related_data *redis_data_ptr = (struct redis_call_related_data*)malloc(sizeof(struct redis_call_related_data));
	redis_data_ptr->ac = ac;
	redis_data_ptr->message = NULL;
	redis_data_ptr->server_ptr = NULL;

	/* Enque the service request */
	enqueueSR(en, new EVTCPServiceRequest(sr_num, cb_evid_num,
									EVTCPServiceRequest::CLOSE_REDIS_CONNECTION, en->getSockfd(), (void*)redis_data_ptr));

	/* And then wake up the loop calls process_service_request */
	ev_async_send(this->_loop, this->_stop_watcher_ptr2);
	/* This will result in invocation of handleServiceRequest
	 * and closeRedisConnection */

	return 0;
}

void EVTCPServer::redisLibevAttach(redisAsyncContext *ac)
{

	//DEBUGPOINT("BEGIN OF THE ENTIRE SAGA\n");

	::redisLibevAttach(this->_loop, ac);

	return;
}

/*
 * FUNCTIONS RELATED TO SENDIND RAW DATA ON
 * ACCEPTED SOCKET
 */

int EVTCPServer::sendRawDataOnAccSocketProcess(EVTCPServiceRequest * sr)
{
	EVAcceptedStreamSocket *tn = getTn(sr->accSockfd());
	if (!tn) {
		DEBUGPOINT("tn not found for [%d]\n", sr->accSockfd());
		std::abort();
	}

	{
		sock_and_data_p_type p = (sock_and_data_p_type)sr->getTaskInputData();
		EVAcceptedStreamSocket *acc_tn = getTn(p->ss.impl()->sockfd());
		if (!acc_tn) {
			DEBUGPOINT("[%d] not an accepted Socket\n", p->ss.impl()->sockfd());
			std::abort();
		}
		if (acc_tn->getSockMode() != EVAcceptedStreamSocket::WEBSOCKET_MODE) {
			DEBUGPOINT("[%d] not Upgraded as a web socket\n", p->ss.impl()->sockfd());
			std::abort();
		}
		acc_tn->pushResData(p->raw_data.data, p->raw_data.size);
		sendDataOnAccSocket(acc_tn, 0);
		p->raw_data.data = NULL;
		p->raw_data.size = 0;

		delete p;
	}

	tn->newdecrNumCSEvents();

	return 0;
}

long EVTCPServer::sendRawDataOnAccSocket(int cb_evid_num, EVAcceptedSocket *en, Net::StreamSocket& accss, void* data, size_t len)
{
	long sr_num = getNextSRSrlNum();

	sock_and_data_p_type p = new sock_and_data_s_type();
	p->raw_data.data = malloc(len);
	memcpy(p->raw_data.data, data, len);
	p->raw_data.size = len;
	p->ss = accss;

	/* Enque the service request */
	enqueueSR(en, new EVTCPServiceRequest(sr_num, cb_evid_num,
									EVTCPServiceRequest::SEND_DATA_ON_ACC_SOCK, en->getSockfd(), p));
	/* And then wake up the loop calls process_service_request */
	ev_async_send(this->_loop, this->_stop_watcher_ptr2);
	/* This will result in invocation of handleServiceRequest
	 * and sendRawDataOnAccSocketProcess */

	return sr_num;
}

int EVTCPServer::trackAsWebSocketProcess(EVTCPServiceRequest * sr)
{
	EVAcceptedStreamSocket *tn = getTn(sr->accSockfd());
	if (!tn) {
		DEBUGPOINT("tn not found for [%d]\n", sr->accSockfd());
		std::abort();
	}

	{
		sock_and_data_p_type p = (sock_and_data_p_type)sr->getTaskInputData();
		EVAcceptedStreamSocket *conn_tn = createEVAccSocket(p->ss);
		conn_tn->setSockUpgradeTo(EVAcceptedStreamSocket::WEBSOCKET);
		conn_tn->setSockMode(EVAcceptedStreamSocket::WEBSOCKET_MODE);
		if (p->raw_data.data) {
			conn_tn->setWsRecvdMsgHandler(std::string((char*)(p->raw_data.data)));
		}
		else {
			ev_io * socket_watcher_ptr = 0;
			socket_watcher_ptr = conn_tn->getSocketWatcher();

			ev_io_stop(this->_loop, socket_watcher_ptr);
			ev_clear_pending(this->_loop, socket_watcher_ptr);
			conn_tn->setState(EVAcceptedStreamSocket::NOT_WAITING);
		}
		conn_tn->getStreamSocketPtr()->impl()->managed(true);

		delete p;
	}

	EVEventNotification * usN = new EVEventNotification(sr->getSRNum(), sr->getCBEVIDNum());
	if ((tn->getProcState()) && tn->srInSession(usN->getSRNum())) {
		enqueue(tn->getIoEventQueue(), (void*)usN);
		tn->newdecrNumCSEvents();
		if (!(tn->sockBusy())) {
			srCompleteEnqueue(tn);
		}
		else {
			tn->setWaitingTobeEnqueued(true);
		}
	}
	else {
		delete usN;
		DEBUGPOINT("REACHED HERE, WHICH MUST NEVER HAVE HAPPENED\n");
		std::abort();
		return -1;
	}

	return 0;
}

long EVTCPServer::trackAsWebSocket(int cb_evid_num, EVAcceptedSocket *en, Net::StreamSocket& connss, const char * msg_handler)
{
	long sr_num = getNextSRSrlNum();
	sock_and_data_p_type p = new sock_and_data_s_type();
	if (msg_handler) {
		p->raw_data.data = strdup(msg_handler);
		p->raw_data.size = strlen(msg_handler);;
	}
	p->ss = connss;

	/* Enque the service request */
	enqueueSR(en, new EVTCPServiceRequest(sr_num, cb_evid_num,
									EVTCPServiceRequest::TRACK_AS_WEBSOCKET, en->getSockfd(), p));
	/* And then wake up the loop calls process_service_request */
	ev_async_send(this->_loop, this->_stop_watcher_ptr2);
	/* This will result in invocation of handleServiceRequest
	 * and trackAsWebSocketProcess */

	return sr_num;
}

/*
 * TIMER RELATED FUNCTIONS START HERE
 */

struct timer_s {
	int time_in_s;
};

static void handle_evtimer_event(EV_P_ ev_timer *w, int revents)
{
	//DEBUGPOINT("Here\n");
	bool ev_occurred = true;
	cb_ref_data_ptr_type cb_ptr = (cb_ref_data_ptr_type)0;

	//if (!ev_is_active(w)) {
		//return ;
	//}

	cb_ptr = (cb_ref_data_ptr_type)w->data;
	/* The below line of code essentially calls
	 * EVTCPServer::handleEVTimerEvent(const bool&)
	 */
	if (cb_ptr) ((cb_ptr->_instance)->*(cb_ptr->_method))(cb_ptr);

	ev_timer_stop(loop, w);

	free(w);
	return;
}

ssize_t EVTCPServer::handleEVTimerEvent(cb_ref_data_ptr_type ref_data)
{
	//DEBUGPOINT("Here\n");
	EVAcceptedStreamSocket *tn = getTn(ref_data->_acc_fd);
	if ((tn->getProcState()) && tn->srInSession(ref_data->_usN->getSRNum())) {
		enqueue(tn->getIoEventQueue(), (void*)ref_data->_usN);
		tn->newdecrNumCSEvents();
		if (!(tn->sockBusy())) {
			srCompleteEnqueue(tn);
		}
		else {
			tn->setWaitingTobeEnqueued(true);
		}
	}
	else {
		delete ref_data->_usN;
		delete ref_data;
		DEBUGPOINT("REACHED HERE, WHICH MUST NEVER HAVE HAPPENED\n");
		std::abort();
		return -1;
	}

	delete ref_data;

	return 0;
}

int EVTCPServer::evTimerProcess(EVTCPServiceRequest * sr)
{
	//DEBUGPOINT("Here\n");
	EVAcceptedStreamSocket *tn = getTn(sr->accSockfd());
	if (!tn) {
		DEBUGPOINT("tn not found for [%d]\n", sr->accSockfd());
		std::abort();
	}

	{
		struct timer_s * p = (struct timer_s *)sr->getTaskInputData();
		ev_timer * timer = (ev_timer *)malloc(sizeof(ev_timer));
		memset(timer, 0, sizeof(ev_timer));

		cb_ref_data_ptr_type ref_data  = new cb_ref_data_type();

		ref_data->_usN = new EVEventNotification(sr->getSRNum(), sr->getCBEVIDNum());
		ref_data->_instance = this;
		ref_data->_acc_fd = sr->accSockfd();
		ref_data->_method = &EVTCPServer::handleEVTimerEvent;

		int timeout = (p->time_in_s);
		//DEBUGPOINT("Here timeout = [%d]\n", timeout);
		if (timeout < 1) {
			DEBUGPOINT("Minimum timer period is 1s\n");
			std::abort();
		}
		timer->data = (void*)ref_data;
		ev_timer_init(timer, handle_evtimer_event, timeout, 0);
		ev_timer_start(this->_loop, timer);

		free(p);
	}
	//tn->incrNumCSEvents();

	return 0;
}


long EVTCPServer::evTimer(int cb_evid_num, EVAcceptedSocket *en, int time_in_s)
{
	long sr_num = getNextSRSrlNum();
	struct timer_s * p = (struct timer_s *)malloc(sizeof(struct timer_s));
	p->time_in_s = time_in_s;
	if (time_in_s < 1) {
		DEBUGPOINT("Minimum timer period is 1s\n");
		std::abort();
	}

	/* Enque the service request */
	enqueueSR(en, new EVTCPServiceRequest(sr_num, cb_evid_num,
									EVTCPServiceRequest::SET_EV_TIMER, en->getSockfd(), p));
	/* And then wake up the loop calls process_service_request */
	ev_async_send(this->_loop, this->_stop_watcher_ptr2);
	/* This will result in invocation of handleServiceRequest
	 * and evTimerProcess */


	return sr_num;
}

int EVTCPServer::shutdownWebSocketProcess(EVTCPServiceRequest * sr)
{
	EVAcceptedStreamSocket *tn = getTn(sr->accSockfd());
	if (!tn) {
		DEBUGPOINT("tn not found for [%d]\n", sr->accSockfd());
		std::abort();
	}

	{
		StreamSocket &ss = sr->getStreamSocket();
		EVAcceptedStreamSocket *conn_tn = getTn(ss.impl()->sockfd());
		ss.impl()->shutdownReceive();

		conn_tn->setShutdownInitiaded();

		monitorDataOnAccSocket(conn_tn);
	}

	tn->newdecrNumCSEvents();

	return 0;
}

long EVTCPServer::shutdownWebSocket(int cb_evid_num, EVAcceptedSocket *en, Net::StreamSocket ss)
{
	long sr_num = getNextSRSrlNum();

	/* Enque the service request */
	enqueueSR(en, new EVTCPServiceRequest(sr_num, cb_evid_num,
									EVTCPServiceRequest::SHUTDOWN_WEBSOCKET, en->getSockfd(), ss));
	/* And then wake up the loop calls process_service_request */
	ev_async_send(this->_loop, this->_stop_watcher_ptr2);
	/* This will result in invocation of handleServiceRequest
	 * and shutdownWebSocketProcess */

	return sr_num;
}

} } // namespace Poco::evnet
