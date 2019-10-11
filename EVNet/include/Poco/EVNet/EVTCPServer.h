//
// EVTCPServer.h
//
// Library: EVNet
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

#include "Poco/Net/Net.h"
#include "Poco/Net/ServerSocket.h"
#include "Poco/EVNet/EVTCPServerConnectionFactory.h"
#include "Poco/Net/TCPServerParams.h"
#include "Poco/RefCountedObject.h"
#include "Poco/AutoPtr.h"
#include "Poco/Runnable.h"
#include "Poco/Thread.h"
#include "Poco/ThreadPool.h"
#include "Poco/Net/TCPServer.h"
#include "Poco/NotificationQueue.h"
#include "Poco/Util/AbstractConfiguration.h"
#include "Poco/EVNet/EVAcceptedStreamSocket.h"
#include "Poco/EVNet/EVConnectedStreamSocket.h"
#include "Poco/EVNet/EVStreamSocketLRUList.h"
#include "Poco/EVNet/EVServer.h"
#include "Poco/EVNet/EVTCPServiceRequest.h"

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
namespace EVNet {

class EVTCPServerDispatcher;

class EVTCPServer;

typedef void (EVTCPServer::*connArrivedMethod)(const bool& );
typedef struct {
	EVTCPServer *objPtr;
	connArrivedMethod connArrived;
} srvrs_io_cb_struct_type , *srvrs_ic_cb_ptr_type;

typedef void (EVTCPServer::*sockReAcquireMethod)(const bool&);
typedef struct {
	EVTCPServer *objPtr;
	sockReAcquireMethod method;
} strms_pc_cb_struct_type , *strms_pc_cb_ptr_type;

struct _strms_io_struct_type;
typedef struct _strms_io_struct_type strms_io_cb_struct_type;
typedef struct _strms_io_struct_type * strms_ic_cb_ptr_type;

typedef ssize_t (EVTCPServer::*fdReadyMethod)(StreamSocket &, const bool& );
typedef ssize_t (EVTCPServer::*cfdReadyMethod)(strms_ic_cb_ptr_type, const bool& );

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

	virtual long submitRequestForConnection(int sr_num, poco_socket_t acc_fd,
								Net::SocketAddress& addr, Net::StreamSocket & css);
		/// To be called whenever another thread wants to make a new connection.

	virtual long submitRequestForClose(int cb_evid_num, poco_socket_t acc_fd, Net::StreamSocket& css);
		/// To be called whenever another thread wants to close an existing connection.

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
	void clearAcceptedSocket(poco_socket_t);
	ssize_t handleConnSocketReadable(strms_ic_cb_ptr_type cb_ptr, const bool& ev_occured);
	ssize_t handleConnSocketWritable(strms_ic_cb_ptr_type cb_ptr, const bool& ev_occured);
	ssize_t handleConnSocketConnected(strms_ic_cb_ptr_type cb_ptr, const bool& ev_occured);
	int makeTCPConnection(EVTCPServiceRequest *);
	int closeTCPConnection(EVTCPServiceRequest * sr);

	typedef std::map<poco_socket_t,EVAcceptedStreamSocket *> ASColMapType;
	typedef std::map<poco_socket_t,EVTCPServiceRequest *> SRColMapType;

	static const std::string NUM_THREADS_CFG_NAME;
	static const std::string RECV_TIME_OUT_NAME;
	static const std::string NUM_CONNECTIONS_CFG_NAME;
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
	void handlePeriodicWakup(const bool& ev_occured);
	long getNextSRSrlNum();

	ServerSocket						_socket;
	EVTCPServerDispatcher*				_pDispatcher;
	TCPServerConnectionFilter::Ptr		_pConnectionFilter;
	Poco::Thread						_thread;
	bool								_stopped;

	srvrs_io_cb_struct_type				_cbStruct;
	struct ev_loop*						_loop;
	ev_async*							stop_watcher_ptr1;
	ev_async*							stop_watcher_ptr2;;
	ev_async*							stop_watcher_ptr3;;

	ASColMapType						_accssColl;
	SRColMapType						_srColl;

	NotificationQueue					_queue;
	NotificationQueue					_service_request_queue;

	EVStreamSocketLRUList				_ssLRUList;
	int									_numThreads;
	int									_numConnections;
	bool								_blocking;
	EVTCPServerConnectionFactory::Ptr	_pConnectionFactory;
	time_t								_receiveTimeOut;

	std::atomic_long					_sr_srl_num;

};

//
// inlines
//
inline long EVTCPServer::getNextSRSrlNum()
{
	long sr_srl_num = 0L;
	long old_srl_num = std::atomic_load(&_sr_srl_num);
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

} } // namespace Poco::EVNet


#endif // EVNet_TCPServer_INCLUDED
