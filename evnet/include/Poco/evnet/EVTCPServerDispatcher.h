//
// EVTCPServerDispatcher.h
//
// Library: evnet
// Package: EVTCPServer
// Module:  EVTCPServerDispatcher
//
// Definition of the EVTCPServerDispatcher class.
//
// Tekenlight Solutions Pvt Ltd.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#ifndef EVNet_EVTCPServerDispatcher_INCLUDED
#define EVNet_EVTCPServerDispatcher_INCLUDED


#include "Poco/Net/Net.h"
#include "Poco/Net/StreamSocket.h"
#include "Poco/evnet/EVTCPServerConnectionFactory.h"
#include "Poco/Net/TCPServerParams.h"
#include "Poco/evnet/EVTCPServer.h"
#include "Poco/Runnable.h"
#include "Poco/NotificationQueue.h"
#include "Poco/ThreadPool.h"
#include "Poco/Mutex.h"


namespace Poco {
namespace evnet {

class Net_API EVTCPServerDispatcher: public Poco::Runnable
	/// A helper class for EVTCPServer that dispatches
	/// connections to server connection threads.
{
public:

	EVTCPServerDispatcher(EVTCPServerConnectionFactory::Ptr pFactory, Poco::ThreadPool& threadPool, Net::TCPServerParams::Ptr pParams, EVServer*  server);
		/// Creates the EVTCPServerDispatcher.
		///
		/// The dispatcher takes ownership of the TCPServerParams object.
		/// If no TCPServerParams object is supplied, the EVTCPServerDispatcher
		/// creates one.

	void duplicate();
		/// Increments the object's reference count.

	void release();
		/// Decrements the object's reference count
		/// and deletes the object if the count
		/// reaches zero.	

	void run();
		/// Runs the dispatcher.
		
	void enqueue(EVAcceptedStreamSocket * socket);
		/// Queues the given socket connection.

	void stop();
		/// Stops the dispatcher.
			
	void joinall();
		/// Joins all threads
			
	int currentThreads() const;
		/// Returns the number of currently used threads.

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

	const Net::TCPServerParams& params() const;
		/// Returns a const reference to the TCPServerParam object.

	Poco::NotificationQueue& queue();
		/// Returns a reference to the Poco::NotificationQueue object.

	void stopall();
		/// Tries to stop all threads in the pool.

	void stopTakingRequests();
		/// Stops enqueueing fresh requests

protected:
	~EVTCPServerDispatcher();
		/// Destroys the EVTCPServerDispatcher.

	void beginConnection();
		/// Updates the performance counters.
		
	void endConnection();
		/// Updates the performance counters.

private:
	EVTCPServerDispatcher();
	EVTCPServerDispatcher(const EVTCPServerDispatcher&);
	EVTCPServerDispatcher& operator = (const EVTCPServerDispatcher&);

	int _rc;
	Net::TCPServerParams::Ptr _pParams;
	int  _currentThreads;
	int  _totalConnections;
	int  _currentConnections;
	int  _maxConcurrentConnections;
	int  _refusedConnections;
	bool _stopped;
	Poco::NotificationQueue         _queue;
	EVTCPServerConnectionFactory::Ptr _pConnectionFactory;
	Poco::ThreadPool&               _threadPool;
	mutable Poco::FastMutex         _mutex;
	EVServer*				_server;
	bool					_stop_taking_requests;
};


//
// inlines
//
inline const Net::TCPServerParams& EVTCPServerDispatcher::params() const
{
	return *_pParams;
}

inline Poco::NotificationQueue & EVTCPServerDispatcher::queue()
{
	return _queue;
}

} } // namespace Poco::evnet


#endif // EVNet_EVTCPServerDispatcher_INCLUDED
