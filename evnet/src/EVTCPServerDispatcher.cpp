//
// EVTCPServerDispatcher.cpp
//
// Library: evnet
// Package: EVTCPServer
// Module:  EVTCPServerDispatcher
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/evnet/EVTCPServer.h"
#include "Poco/evnet/EVTCPServerDispatcher.h"
#include "Poco/evnet/EVTCPServerConnectionFactory.h"
#include "Poco/Net/NetException.h"
#include "Poco/Notification.h"
#include "Poco/AutoPtr.h"
#include <memory>

#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>

using Poco::Net::TCPServerConnectionFactory;
using Poco::Notification;
using Poco::FastMutex;
using Poco::AutoPtr;

using Poco::Net::NoMessageException;
using Poco::Net::MessageException;

namespace Poco {
namespace evnet {

void tcpd_signal_handler(int signal)
{
	DEBUGPOINT("Here\n");
	std::abort();
	return ;
}


class TCPConnectionNotification: public Notification
{
public:
	TCPConnectionNotification(EVAcceptedStreamSocket * socket):
		_socket(socket),
		_sockfd(socket->getSockfd())
	{
	}
	
	~TCPConnectionNotification()
	{
	}

	
	EVAcceptedStreamSocket * socket() 
	{
		return _socket;
	}

	poco_socket_t sockfd()
	{
		return _sockfd;
	}

private:
	EVAcceptedStreamSocket*		 _socket;
	poco_socket_t				_sockfd;
};

EVTCPServerDispatcher::EVTCPServerDispatcher(EVTCPServerConnectionFactory::Ptr pFactory,
				Poco::ThreadPool& threadPool, Net::TCPServerParams::Ptr pParams, EVServer* server):
	_rc(1),
	_pParams(pParams),
	_currentThreads(0),
	_totalConnections(0),
	_currentConnections(0),
	_maxConcurrentConnections(0),
	_refusedConnections(0),
	_stopped(false),
	_pConnectionFactory(pFactory),
	_threadPool(threadPool),
	_server(server)
{
	poco_check_ptr (pFactory);

	if (!_pParams)
		_pParams = new Net::TCPServerParams;
	
	if (_pParams->getMaxThreads() == 0)
		_pParams->setMaxThreads(threadPool.capacity());
}


EVTCPServerDispatcher::~EVTCPServerDispatcher()
{
}


void EVTCPServerDispatcher::duplicate()
{
	_mutex.lock();
	++_rc;
	_mutex.unlock();
}


void EVTCPServerDispatcher::release()
{
	_mutex.lock();
	int rc = --_rc;
	_mutex.unlock();
	if (rc == 0) delete this;
}


void EVTCPServerDispatcher::run()
{
	AutoPtr<EVTCPServerDispatcher> guard(this, true); // ensure object stays alive

	int idleTime = (int) _pParams->getThreadIdleTime().totalMilliseconds();

	//signal(SIGSEGV, tcpd_signal_handler);

	for (;;)
	{
		AutoPtr<Notification> pNf = _queue.waitDequeueNotification(idleTime);
		if (pNf) {
			TCPConnectionNotification* pCNf = dynamic_cast<TCPConnectionNotification*>(pNf.get());
			if (pCNf)
			{
				try {
#ifndef POCO_ENABLE_CPP11
					std::auto_ptr<evnet::EVTCPServerConnection>
							pConnection(_pConnectionFactory->createConnection(pCNf->socket()->getStreamSocket()));
#else
					std::unique_ptr<evnet::EVTCPServerConnection>
							pConnection(_pConnectionFactory->createConnection(pCNf->socket()->getStreamSocket()));
#endif // POCO_ENABLE_CPP11
					poco_check_ptr(pConnection.get());
					beginConnection();
					/* pCNf is TCPConnectionNotification and
					 * pCNf->socket() is EVAcceptedStreamSocket.
					 * */
					pCNf->socket()->getProcState()->setReqMemStream(pCNf->socket()->getReqMemStream());
					pCNf->socket()->getProcState()->setResMemStream(pCNf->socket()->getResMemStream());
					pCNf->socket()->getProcState()->setUpstreamEventQ(pCNf->socket()->getUpstreamIoEventQueue());
					pConnection->setProcState(pCNf->socket()->getProcState());
					pConnection->start(true);
					//pConnection->start();
					endConnection();
					_server->receivedDataConsumed(pCNf->sockfd());
				}
				catch (NoMessageException&) {
					DEBUGPOINT("Here %d\n", pCNf->sockfd());
					endConnection();
					_server->errorInReceivedData(pCNf->sockfd(),true);
				}
				catch (MessageException&) {
					DEBUGPOINT("Here %d\n", pCNf->sockfd());
					endConnection();
					_server->errorInReceivedData(pCNf->sockfd(),true);
				}
				catch (Poco::Exception& e) {
					DEBUGPOINT("Here %d %s\n", pCNf->sockfd(), e.what());
					endConnection();
					_server->errorInReceivedData(pCNf->sockfd(),true);
				}
				catch (...) {
					DEBUGPOINT("Here %d\n", pCNf->sockfd());
					endConnection();
					_server->errorInReceivedData(pCNf->sockfd(),true);
				}
			}
		}


		FastMutex::ScopedLock lock(_mutex);
		if (_stopped || (_currentThreads > 1 && _queue.empty()))
		{
			--_currentThreads;
			break;
		}
	}
}


namespace
{
	static const std::string threadName("EVTCPServerConnection");
}

	
//void EVTCPServerDispatcher::enqueue(const Net::StreamSocket& socket)
void EVTCPServerDispatcher::enqueue(EVAcceptedStreamSocket  * evAccSocket)
{
	FastMutex::ScopedLock lock(_mutex);

	/* default maxQueued is 64. */
	evAccSocket->setWaitingTobeEnqueued(false);
	if (_queue.size() < _pParams->getMaxQueued())
	{
		_queue.enqueueNotification(new TCPConnectionNotification(evAccSocket));
		if (!_queue.hasIdleThreads() && _currentThreads < _pParams->getMaxThreads())
		{
			try
			{
				_threadPool.startWithPriority(_pParams->getThreadPriority(), *this, threadName);
				++_currentThreads;
			}
			catch (Poco::Exception&)
			{
				// no problem here, connection is already queued
				// and a new thread might be available later.
			}
		}
	}
	else
	{
		++_refusedConnections;
		/* In case the queue is full, the message cannot be processed.
		 * It means that the server is overwhelmed.
		 * Closing connection in that case.
		 * */
		_server->errorInReceivedData(evAccSocket->getSockfd(),true);
	}
}


void EVTCPServerDispatcher::stop()
{
	_stopped = true;
	_queue.clear();
	_queue.wakeUpAll();
}


int EVTCPServerDispatcher::currentThreads() const
{
	FastMutex::ScopedLock lock(_mutex);
	
	return _currentThreads;
}

int EVTCPServerDispatcher::maxThreads() const
{
	FastMutex::ScopedLock lock(_mutex);
	
	return _threadPool.capacity();
}


int EVTCPServerDispatcher::totalConnections() const
{
	FastMutex::ScopedLock lock(_mutex);
	
	return _totalConnections;
}


int EVTCPServerDispatcher::currentConnections() const
{
	FastMutex::ScopedLock lock(_mutex);
	
	return _currentConnections;
}


int EVTCPServerDispatcher::maxConcurrentConnections() const
{
	FastMutex::ScopedLock lock(_mutex);
	
	return _maxConcurrentConnections;
}


int EVTCPServerDispatcher::queuedConnections() const
{
	return _queue.size();
}


int EVTCPServerDispatcher::refusedConnections() const
{
	FastMutex::ScopedLock lock(_mutex);
	
	return _refusedConnections;
}


void EVTCPServerDispatcher::beginConnection()
{
	FastMutex::ScopedLock lock(_mutex);
	
	++_totalConnections;
	++_currentConnections;
	if (_currentConnections > _maxConcurrentConnections)
		_maxConcurrentConnections = _currentConnections;
}


void EVTCPServerDispatcher::endConnection()
{
	FastMutex::ScopedLock lock(_mutex);

	--_currentConnections;
}

} } // namespace Poco::evnet
