//
// EVTCPServer.h
//
// Library: evnet
// Package: EVTCPServer
// Module:  EVTCPServer
//
// Definition of the EVTCPServer class.
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#ifndef EVNet_EVTCPServer_INCLUDED
#define EVNet_EVTCPServer_INCLUDED

#include <atomic>

#include <ev.h>
#include <map>

#include <ev_queue.h>
#include <chunked_memory_stream.h>
#include <thread_pool.h>

#include "Poco/Net/Net.h"
#include "Poco/Net/ServerSocket.h"
#include "Poco/evnet/EVTCPServerConnectionFactory.h"
#include "Poco/Net/TCPServerParams.h"
#include "Poco/RefCountedObject.h"
#include "Poco/AutoPtr.h"
#include "Poco/Runnable.h"
#include "Poco/Thread.h"
#include "Poco/ThreadPool.h"
#include "Poco/Net/TCPServer.h"
#include "Poco/NotificationQueue.h"
#include "Poco/Util/AbstractConfiguration.h"
#include "Poco/evnet/EVAcceptedStreamSocket.h"
#include "Poco/evnet/EVConnectedStreamSocket.h"
#include "Poco/evnet/EVStreamSocketLRUList.h"
#include "Poco/evnet/EVServer.h"
#include "Poco/evnet/EVTCPServiceRequest.h"
#include "Poco/evnet/EVUpstreamEventNotification.h"

#define DEFAULT_NUM_AUXJOB_THREADS 4

namespace Poco { namespace Net {
	class StreamSocket;
} }

using Poco::Net::StreamSocket;
using Poco::Net::TCPServerParams;
using Poco::Net::ServerSocket;
using Poco::Net::StreamSocket;
using Poco::Net::Socket;
using Poco::Net::AddressFamily;
using Poco::Net::TCPServerConnectionFilter;
using Poco::NotificationQueue;
using Poco::Util::AbstractConfiguration;

namespace Poco {
namespace evnet {

class EVTCPServerDispatcher;

class EVTCPServer;

typedef void (EVTCPServer::*connArrivedMethod)(const bool& );
typedef struct {
	EVTCPServer *objPtr;
	connArrivedMethod connArrived;
} srvrs_io_cb_struct_type , *srvrs_io_cb_ptr_type;

typedef void (EVTCPServer::*sockReAcquireMethod)(const bool&);
typedef struct {
	EVTCPServer *objPtr;
	sockReAcquireMethod method;
} strms_pc_cb_struct_type , *strms_pc_cb_ptr_type;

struct _strms_io_struct_type;
typedef struct _strms_io_struct_type strms_io_cb_struct_type;
typedef struct _strms_io_struct_type * strms_io_cb_ptr_type;

typedef ssize_t (EVTCPServer::*fdReadyMethod)(StreamSocket &, const bool& );
typedef ssize_t (EVTCPServer::*cfdReadyMethod)(strms_io_cb_ptr_type, const bool& );

struct _strms_io_struct_type {
	long sr_num; // The identifier of service request, to be used in case of requests from worker threads
	int cb_evid_num; // Event id to be invoked in the worker, when this SR completes.
	EVTCPServer *objPtr;
	fdReadyMethod dataAvailable;
	fdReadyMethod socketWritable;
	cfdReadyMethod connSocketReadable;
	cfdReadyMethod connSocketWritable;
	StreamSocket *ssPtr;
	EVConnectedStreamSocket *cn;
};

typedef struct _cb_ref_data {
	_cb_ref_data() : _instance(0), _usN(0), _acc_fd(-1) {}
	EVTCPServer* _instance;
	EVUpstreamEventNotification *_usN;
	poco_socket_t _acc_fd;
} cb_ref_data_type, * cb_ref_data_ptr_type;

struct _dns_io_struct {
	struct _input {
		_input(): _host_name(0), _serv_name(0), _ref_data(0) { memset(&_hints, 0, sizeof(struct addrinfo)); }
		const char* _host_name;
		const char* _serv_name;
		struct addrinfo _hints;
		void *_ref_data;
	} _in;
	struct _output {
		_output(): _result(0), _return_value(0), _errno(0) {}
		struct addrinfo* _result;
		int _return_value;
		int _errno;
	} _out;
};

typedef struct _dns_io_struct dns_io_struct_type;
typedef struct _dns_io_struct* dns_io_ptr_type;

struct _file_event_status {
	poco_socket_t					_acc_fd;
	EVUpstreamEventNotification*	_usN;
	_file_event_status(): _acc_fd(-1), _usN(0) {}
};

typedef struct _file_event_status file_event_status_s;
typedef struct _file_event_status* file_event_status_p;

class Net_API EVTCPServer: public Poco::Runnable, public EVServer
	/// This class implements a multithreaded TCP server.
	///
	/// The server uses a ServerSocket to listen for incoming
	/// connections. The ServerSocket must have been bound to
	/// an address before it is passed to the EVTCPServer constructor.
	/// Additionally, the ServerSocket must be put into listening
	/// state before the EVTCPServer is started by calling the start()
	/// method.
	///
	/// The server uses a thread pool to assign threads to incoming
	/// connections. Before incoming connections are assigned to
	/// a connection thread, they are put into a queue.
	/// Connection threads fetch new connections from the queue as soon
	/// as they become free. Thus, a connection thread may serve more
	/// than one connection.
	///
	/// As soon as a connection thread fetches the next connection from
	/// the queue, it creates a EVTCPServerConnection object for it
	/// (using the EVTCPServerConnectionFactory passed to the constructor)
	/// and calls the EVTCPServerConnection's start() method. When the
	/// start() method returns, the connection object is deleted.
	///
	/// The number of connection threads is adjusted dynamically, depending
	/// on the number of connections waiting to be served.
	///
	/// It is possible to specify a maximum number of queued connections.
	/// This prevents the connection queue from overflowing in the 
	/// case of an extreme server load. In such a case, connections that
	/// cannot be queued are silently and immediately closed.
	///
	/// EVTCPServer uses a separate thread to accept incoming connections.
	/// Thus, the call to start() returns immediately, and the server
	/// continues to run in the background.
	///
	/// To stop the server from accepting new connections, call stop().
	///
	/// After calling stop(), no new connections will be accepted and
	/// all queued connections will be discarded.
	/// Already served connections, however, will continue being served.
{
public:
	EVTCPServer(EVTCPServerConnectionFactory::Ptr pFactory, Poco::UInt16 portNumber = 0, TCPServerParams::Ptr pParams = 0);
		/// Creates the EVTCPServer, with ServerSocket listening on the given port.
		/// Default port is zero, allowing any available port. The port number
		/// can be queried through EVTCPServer::port() member.
		///
		/// The server takes ownership of the EVTCPServerConnectionFactory
		/// and deletes it when it's no longer needed.
		///
		/// The server also takes ownership of the TCPServerParams object.
		/// If no TCPServerParams object is given, the server's TCPServerDispatcher
		/// creates its own one.
		///
		/// New threads are taken from the default thread pool.

	EVTCPServer(EVTCPServerConnectionFactory::Ptr pFactory, const ServerSocket& socket, TCPServerParams::Ptr pParams = 0);
		/// Creates the EVTCPServer, using the given ServerSocket.
		///
		/// The server takes ownership of the EVTCPServerConnectionFactory
		/// and deletes it when it's no longer needed.
		///
		/// The server also takes ownership of the TCPServerParams object.
		/// If no TCPServerParams object is given, the server's TCPServerDispatcher
		/// creates its own one.
		///
		/// New threads are taken from the default thread pool.

	EVTCPServer(EVTCPServerConnectionFactory::Ptr pFactory, Poco::ThreadPool& threadPool, const ServerSocket& socket, TCPServerParams::Ptr pParams = 0);
		/// Creates the EVTCPServer, using the given ServerSocket.
		///
		/// The server takes ownership of the EVTCPServerConnectionFactory
		/// and deletes it when it's no longer needed.
		///
		/// The server also takes ownership of the TCPServerParams object.
		/// If no TCPServerParams object is given, the server's TCPServerDispatcher
		/// creates its own one.
		///
		/// New threads are taken from the given thread pool.

	virtual ~EVTCPServer();
		/// Destroys the EVTCPServer and its EVTCPServerConnectionFactory.

	const TCPServerParams& params() const;
		/// Returns a const reference to the TCPServerParam object
		/// used by the server's TCPServerDispatcher.	

	void start();
		/// Starts the server. A new thread will be
		/// created that waits for and accepts incoming
		/// connections.
		///
		/// Before start() is called, the ServerSocket passed to
		/// EVTCPServer must have been bound and put into listening state.

	void stop();
		/// Stops the server.
		///
		/// No new connections will be accepted.
		/// Already handled connections will continue to be served.
		///
		/// Once the server has been stopped, it cannot be restarted.
		
	int currentThreads() const;
		/// Returns the number of currently used connection threads.

	int maxThreads() const;
		/// Returns the maximum number of threads available.

	int totalConnections() const;
		/// Returns the total number of handled connections.
		
	int currentConnections() const;
		/// Returns the number of currently handled connections.

	int maxConcurrentConnections() const;
		/// Returns the maximum number of concurrently handled connections.	
		
	int queuedConnections() const;
		/// Returns the number of queued connections.

	int refusedConnections() const;
		/// Returns the number of refused connections.

	const ServerSocket& socket() const;
		/// Returns the underlying server socket.
	
	Poco::UInt16 port() const;
		/// Returns the port the server socket listens on.

	void setConnectionFilter(const TCPServerConnectionFilter::Ptr& pFilter);
		/// Sets a TCPServerConnectionFilter. Can also be used to remove
		/// a filter by passing a null pointer.
		///
		/// To avoid a potential race condition, the filter must
		/// be set before the EVTCPServer is started. Trying to set
		/// the filter after start() has been called will trigger
		/// an assertion.
		
	TCPServerConnectionFilter::Ptr getConnectionFilter() const;
		/// Returns the TCPServerConnectionFilter set with setConnectionFilter(), 
		/// or null pointer if no filter has been set.

	void justEnqueue(EVAcceptedStreamSocket* tn);
	void srCompleteEnqueue(EVAcceptedStreamSocket* tn);
	void srComplete(EVAcceptedStreamSocket* );
	void enqueueSR(EVAcceptedSocket *tn, EVTCPServiceRequest * sr);
	long submitRequestForPoll(int cb_evid_num, EVAcceptedSocket *tn, Net::StreamSocket& css, int poll_for);
	virtual long submitRequestForConnection(int sr_num, EVAcceptedSocket *tn,
								Net::SocketAddress& addr, Net::StreamSocket & css);
	virtual long submitRequestForHostResolution(int cb_evid_num, EVAcceptedSocket *tn,
								const char* domain_name, const char* serv_name);
		/// To be called whenever another thread wants to make a new connection.

	virtual long submitRequestForClose(EVAcceptedSocket *tn, Net::StreamSocket& css);
		/// To be called whenever another thread wants to close an existing connection.

	virtual long submitRequestForSendData(EVAcceptedSocket *tn, Net::StreamSocket& css);
		/// To be called whenver a worker thread wants to send data
		/// to a server it has opened connection with.
	virtual long submitRequestForRecvData(int cb_evid_num, EVAcceptedSocket *tn, Net::StreamSocket& css);
		/// To be called whenver a worker thread wants to recv data
		/// to a server it has opened connection with.
	void postHostResolution(dns_io_ptr_type dio_ptr);
		/// To handle result of host resolution in the context of EVTCPServer

	void postGenericTaskComplete(poco_socket_t acc_fd, EVUpstreamEventNotification *usN);
		/// To handle post processing of generic task

	void pushFileEvent(int fd, int completed_oper);
		/// To handle the event of file operation completion

	virtual long submitRequestForTaskExecution(int cb_evid_num, EVAcceptedSocket *tn, generic_task_handler_t tf, void* input_data);
		/// Function to submit a generic task for asynchronous execution

	virtual  long submitRequestForTaskExecutionNR(generic_task_handler_nr_t tf, void* input_data);
		/// Function to submit a generic task for asynchronous execution, this function does not call back or return.

	virtual long notifyOnFileOpen(int cb_evid_num, EVAcceptedSocket *tn, int fd);
	virtual long notifyOnFileRead(int cb_evid_num, EVAcceptedSocket *tn, int fd);
		/// Functions needed for asynchronous file operations.

protected:
	void run();
		/// Runs the server. The server will run until
		/// the stop() method is called, or the server
		/// object is destroyed, which implicitly calls
		/// the stop() method.

	static std::string threadName(const ServerSocket& socket);
		/// Returns a thread name for the server thread.

	poco_socket_t sockfd() const;
		/// Returns the underlying server socket file descriptor

private:
	void init();
	void clearAcceptedSocket(poco_socket_t);
	ssize_t handleConnSocketWriteReady(strms_io_cb_ptr_type cb_ptr, const bool& ev_occured);
	ssize_t handleConnSocketReadReady(strms_io_cb_ptr_type cb_ptr, const bool& ev_occured);
	ssize_t handleConnSocketReadable(strms_io_cb_ptr_type cb_ptr, const bool& ev_occured);
	ssize_t handleConnSocketWriteable(strms_io_cb_ptr_type cb_ptr, const bool& ev_occured);
	void handleHostResolved(const bool& ev_occured);
	void handleGenericTaskComplete(const bool& ev_occured);
	void handleFileEvtOccured(const bool& ev_occured);
	ssize_t handleConnSocketConnected(strms_io_cb_ptr_type cb_ptr, const bool& ev_occured);
	int makeTCPConnection(EVTCPServiceRequest *);
	int resolveHost(EVTCPServiceRequest * sr);
	int resolveHost(EVAcceptedStreamSocket* tn, EVTCPServiceRequest* sr);
	int initiateGenericTask(EVTCPServiceRequest * sr);
	int initiateGenericTask(EVAcceptedStreamSocket * tn, EVTCPServiceRequest * sr);
	int initiateGenericTaskNR(EVTCPServiceRequest * sr);
	int pollFileOpenEvent(EVTCPServiceRequest * sr);
	int pollFileReadEvent(EVTCPServiceRequest * sr);
	int makeTCPConnection(EVConnectedStreamSocket * cn);
	int sendDataOnConnSocket(EVTCPServiceRequest *);
	int recvDataOnConnSocket(EVTCPServiceRequest *);
	int closeTCPConnection(EVTCPServiceRequest * sr);
	int pollSocketForReadOrWrite(EVTCPServiceRequest * sr);

	typedef std::map<poco_socket_t,EVAcceptedStreamSocket *> ASColMapType;
	typedef std::map<int,file_event_status_s> FileEvtSubscrMap;

	static const std::string NUM_THREADS_CFG_NAME;
	static const std::string RECV_TIME_OUT_NAME;
	static const std::string NUM_CONNECTIONS_CFG_NAME;
	static const std::string USE_IPV6_FOR_CONN;
	static const std::string SERVER_PREFIX_CFG_NAME;

	static const int TCP_BUFFER_SIZE = 4096;

	EVTCPServer();
	EVTCPServer(const EVTCPServer&);
	EVTCPServer& operator = (const EVTCPServer&);
	
	void handleConnReq(const bool& abortCurrent);
		/// Function to handle the event of socket receiving a connection request.
	ssize_t handleAccSocketWritable(StreamSocket & streamSocket, const bool& ev_occured);
		/// Function to handle the event of stream socket becoming writable.
		/// Returns the number of bytes remaining to be written.
	ssize_t handleAccSocketReadable(StreamSocket & streamSocket, const bool& ev_occured);
		/// Function to handle the event of stream socket receiving data request.
	virtual void dataReadyForSend(int fd);
		/// Function to handle the event of data being ready to be sent on a socket.
	void sendDataOnAccSocket(EVAcceptedStreamSocket *tn);
		/// Function to data on a sockets for which data is ready.
	virtual void receivedDataConsumed(int fd);
		/// Function to handle the event of completion of one request.
	void monitorDataOnAccSocket(EVAcceptedStreamSocket *tn);
		/// Function to add the StreamSocket back to listening mode
	void somethingHappenedInAnotherThread(const bool& flag);
		/// Function to add the StreamSocket back to listening mode
	void handleServiceRequest(const bool& ev_occured);
		// Function to request a service from TCP Server
	void errorInAuxProcesing(poco_socket_t fd, bool connInErr);
	virtual void errorInReceivedData(poco_socket_t fd, bool connInErr);
		/// Function to handle the event of completion of one request with exceptions.
	void errorWhileReceiving(poco_socket_t fd, bool connInErr);
		/// Function to handle the event of error in receiving data from downstream socket.
	void errorWhileSending(poco_socket_t fd, bool connInErr);
		/// Function to handle the event of error in sending data to downstream socket.
	void freeClear();
		/// Function to cleanup the memory allocated for socket management.
	AbstractConfiguration& appConfig();
	ssize_t receiveData(int fd, void * chptr, size_t size);
	ssize_t receiveData(StreamSocket&, void * chptr, size_t size);
	ssize_t sendData(int fd, void * chptr, size_t size);
	ssize_t sendData(StreamSocket&, void * chptr, size_t size);
	void handlePeriodicWakeup(const bool& ev_occured);
	unsigned long getNextSRSrlNum();
	EVAcceptedStreamSocket* getTn(poco_socket_t fd);

	ServerSocket						_socket;
	EVTCPServerDispatcher*				_pDispatcher;
	TCPServerConnectionFilter::Ptr		_pConnectionFilter;
	Poco::Thread						_thread;
	bool								_stopped;

	srvrs_io_cb_struct_type				_cbStruct;
	struct ev_loop*						_loop;
	ev_async*							_stop_watcher_ptr1;
	ev_async*							_stop_watcher_ptr2;;
	ev_async*							_stop_watcher_ptr3;;
	ev_async*							_dns_watcher_ptr;
	ev_async*							_gen_task_compl_watcher_ptr;
	ev_async*							_file_evt_watcher_ptr;

	ASColMapType						_accssColl;
	FileEvtSubscrMap					_file_evt_subscriptions;

	NotificationQueue					_queue;
	NotificationQueue					_service_request_queue;
	ev_queue_type						_aux_tc_queue; // Auxillary task completion queue
	ev_queue_type						_file_evt_queue; // File Event completion queue
	ev_queue_type						_host_resolve_queue; // Host resolution completion queue

	EVStreamSocketLRUList				_ssLRUList;
	int									_numThreads;
	int									_numConnections;
	bool								_blocking;
	EVTCPServerConnectionFactory::Ptr	_pConnectionFactory;
	time_t								_receiveTimeOut;

	std::atomic_ulong					_sr_srl_num;
	thread_pool_type					_thread_pool;
	bool								_use_ipv6_for_conn;
};

//
// inlines
//

inline EVAcceptedStreamSocket* EVTCPServer::getTn(poco_socket_t fd)
{
	auto it = _accssColl.find(fd);
	if (_accssColl.end() != it) return it->second;
	else return NULL;
}

inline unsigned long EVTCPServer::getNextSRSrlNum()
{
	unsigned long sr_srl_num = 0L;
	unsigned long old_srl_num = std::atomic_load(&_sr_srl_num);
	do {
		sr_srl_num = old_srl_num + 1;
	} while (!std::atomic_compare_exchange_strong(&_sr_srl_num, &old_srl_num, sr_srl_num)) ;

	return sr_srl_num;
}

inline const ServerSocket& EVTCPServer::socket() const
{
	return _socket;
}

inline poco_socket_t EVTCPServer::sockfd() const
{
	return socket().impl()->sockfd();
}


inline Poco::UInt16 EVTCPServer::port() const
{
	return _socket.address().port();
}

} } // namespace Poco::evnet


#endif // EVNet_TCPServer_INCLUDED
