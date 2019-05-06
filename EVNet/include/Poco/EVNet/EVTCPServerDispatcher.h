//
// EVTCPServerDispatcher.h
//
// Library: EVNet
// Package: EVTCPServer
// Module:  EVTCPServerDispatcher
//
// Definition of the EVTCPServerDispatcher class.
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#ifndef EVNet_EVTCPServerDispatcher_INCLUDED
#define EVNet_EVTCPServerDispatcher_INCLUDED


#include "Poco/Net/Net.h"
#include "Poco/Net/StreamSocket.h"
#include "Poco/EVNet/EVTCPServerConnectionFactory.h"
#include "Poco/Net/TCPServerParams.h"
#include "Poco/EVNet/EVTCPServer.h"
#include "Poco/Runnable.h"
#include "Poco/NotificationQueue.h"
#include "Poco/ThreadPool.h"
#include "Poco/Mutex.h"


namespace Poco {
namespace EVNet {

typedef void (EVTCPServer::*reqComplMthd)(Net::StreamSocket &);
typedef void (EVTCPServer::*reqExcpMthd)(Net::StreamSocket &, bool);
typedef struct {
	EVTCPServer *objPtr;
	reqComplMthd reqComMthd;
	reqExcpMthd reqExcMthd;
} reqComplEvntHandler , *reqComplEvntHandlerPtr;

class Net_API EVTCPServerDispatcher: public Poco::Runnable
	/// A helper class for EVTCPServer that dispatches
	/// connections to server connection threads.
{
public:

	EVTCPServerDispatcher(EVTCPServerConnectionFactory::Ptr pFactory, Poco::ThreadPool& threadPool, Net::TCPServerParams::Ptr pParams, reqComplEvntHandler & evtHandle);
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
	reqComplEvntHandler				_cbHandle;
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

} } // namespace Poco::EVNet


#endif // EVNet_EVTCPServerDispatcher_INCLUDED
