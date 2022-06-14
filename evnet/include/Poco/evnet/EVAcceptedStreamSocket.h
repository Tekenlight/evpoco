//
// EVAcceptedStreamSocket.h
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
#include <atomic>
#include <chunked_memory_stream.h>
#include <ev_queue.h>
#include "Poco/Net/Net.h"
#include "Poco/Net/StreamSocket.h"
#include "Poco/evnet/EVAcceptedSocket.h"
#include "Poco/evnet/EVProcessingState.h"

using Poco::Net::StreamSocket;

#ifndef POCO_EVNET_EVACCEPTEDSTREAMSOCKET_H_INCLUDED
#define POCO_EVNET_EVACCEPTEDSTREAMSOCKET_H_INCLUDED

namespace Poco{ namespace evnet {


class Net_API EVAcceptedStreamSocket : public EVAcceptedSocket
	/// This class is acts as an element of the list of
	/// StreamSockets opened in an event driven TCP server
	///
	/// When the server accepts a connection request from
	/// a server socket. A new StreamSocket is created.
	/// That along with a libev watcher for that socket
	/// are held in this object and then added to a list
	/// within the EVTCPServer.
	///
	/// When EVTCPServer itself goes out of scope all the accpted StreamSockets and the correspnding wathcers
	/// are freed.
{
public:
	typedef enum {
		NOT_WAITING = 0
		,WAITING_FOR_READ = EV_READ
		,WAITING_FOR_WRITE = EV_WRITE
		,WAITING_FOR_READWRITE = EV_READ|EV_WRITE
	} accepted_sock_state;

	typedef enum {
		NONE = 0,
		WEBSOCKET,
		HTTP2
	} socket_upgrade_to_enum;

	enum PROTOCOL {
		HTTP = 0, COMMAND_LINE_MODE = 1, WEBSOCKET_MODE = 2, HTTP2_MODE = 3
	};

	enum TASK_TYPE {
		CLIENT_REQUEST = 0, ASYNC_TASK
	};

	EVAcceptedStreamSocket(StreamSocket & streamSocket);
	EVAcceptedStreamSocket(int CL_rd_fd, int CL_wr_fd);
	~EVAcceptedStreamSocket();

	StreamSocket & getOutStreamSocket();
	StreamSocket & getStreamSocket();
	/// This method gives the stored StreamSocket

	void setStreamSocket(StreamSocket &ss);
	/// This method gives the stored StreamSocket

	StreamSocket *  getStreamSocketPtr();
	/// This method gives a pointer to the stored StreamSocket

	ev_io * getSocketWatcher();
	/// This method gets the socket watcher that was associated with this socket.

	virtual poco_socket_t getSockfd();
	/// This returns the socket fd of the stream socket
	/// The fd is needed to interface with libev.

	time_t getTimeOfLastUse();
	/// This returns the last time stamp when this stream socket was used for 
	/// some request processing

	void setTimeOfLastUse();
	/// This sets the last time stamp for this stream socket
	//
	
	void setSockFree();
	// Sets the _sockBusy flag to false.
	//
	
	void setSockBusy();
	// Sets the _sockBusy flag to true.

	size_t pushReqData(void * buffer, size_t size);
	size_t pushResData(void * buffer, size_t size);
	// Transfers the bytes read from socket to the stream.

	bool reqDataAvlbl();
	bool resDataAvlbl();
	
	bool sockBusy();

	void setProcState(EVProcessingState* procState);

	EVProcessingState* getProcState();

	void setNextPtr(EVAcceptedStreamSocket * ptr);
	void setPrevPtr(EVAcceptedStreamSocket * ptr);
	EVAcceptedStreamSocket * getNextPtr();
	EVAcceptedStreamSocket * getPrevPtr();
	chunked_memory_stream * getReqMemStream();
	chunked_memory_stream * getResMemStream();
	void deleteState();
	void setClientAddress(Net::SocketAddress addr);
	void setServerAddress(Net::SocketAddress addr);
	Net::SocketAddress& clientAddress();
	Net::SocketAddress& serverAddress();

	void setEventLoop(struct ev_loop* loop);
	struct ev_loop* getEventLoop();
	void setSocketWatcher(ev_io *socket_watcher_ptr);

	int getTaskType();
	void setTaskType(int t);
	bool getCLState();
	void setCLState(bool state);
	accepted_sock_state getState();
	void setState(accepted_sock_state state);
	inline void setSockInError();
	inline bool sockInError();
	ev_queue_type getIoEventQueue();
#if 0
	void decrNumCSEvents();
	void incrNumCSEvents();
	bool pendingCSEvents();
#endif
	void newdecrNumCSEvents();
	void newresetNumCSEvents();
	virtual void newincrNumCSEvents();
	bool newpendingCSEvents();
	bool srInSession(unsigned long sr_srl_num);
	void setBaseSRSrlNum(unsigned long sr_srl_num);
	void setWaitingTobeEnqueued(bool flg);
	bool waitingTobeEnqueued();
	int getSockMode();
	void setSockMode(int);
	int getCLRdFd();
	int getCLWrFd();
	socket_upgrade_to_enum getSockUpgradeTo();
	void setSockUpgradeTo(socket_upgrade_to_enum to);
	std::string getWsRecvdMsgHandler();
	void setWsRecvdMsgHandler(std::string s);
	bool shutdownInitiated();
	void setShutdownInitiaded();

private:
	int							_sock_mode;
	int							_clRdFd;
	int							_clWrFd;
	poco_socket_t				_sockFd;
	struct ev_loop*				_loop;
	ev_io*						_socket_watcher;
	StreamSocket				_streamSocket;
	StreamSocket				_out_streamSocket;
	Net::SocketAddress			_clientAddress;
	Net::SocketAddress			_serverAddress;
	time_t						_timeOfLastUse;
	EVAcceptedStreamSocket*		_prevPtr;
	EVAcceptedStreamSocket*		_nextPtr;
	EVProcessingState*			_reqProcState;
	chunked_memory_stream*		_req_memory_stream;
	chunked_memory_stream*		_res_memory_stream;
	ev_queue_type				_event_queue;

	/* Status indicators */
	accepted_sock_state			_state; /* Tells whether the socket is waiting for OS event or not */
	bool						_cl_state; /* Tells whether the socket is to be closed or not */
	int							_socketInError; /* Tells if an error is observed while processing request
												   on this socket. */
	bool						_sockBusy; /* Tells if the socket is in custody of a worker thread */
	std::atomic_int				_new_active_cs_events; /* Tells how many SR requests are pending on this sock */
	unsigned long				_base_sr_srl_num;
	bool						_waiting_tobe_enqueued;
	socket_upgrade_to_enum		_socket_upgraded_to;
	std::string					_ws_recvd_msg_handler; /* Name of the request handler in case of received frames
														  on websockets. */
	bool						_shutdown_initiated;
	int							_task_type;
};

inline int EVAcceptedStreamSocket::getTaskType()
{
	return this->_task_type;
}

inline void EVAcceptedStreamSocket::setTaskType(int t)
{
	this->_task_type = t;
}

inline bool EVAcceptedStreamSocket::shutdownInitiated()
{
	return _shutdown_initiated;
}

inline void EVAcceptedStreamSocket::setShutdownInitiaded()
{
	_shutdown_initiated = true;
}

inline std::string EVAcceptedStreamSocket::getWsRecvdMsgHandler()
{
	return _ws_recvd_msg_handler;
}

inline void EVAcceptedStreamSocket::setWsRecvdMsgHandler(std::string to)
{
	_ws_recvd_msg_handler = to;
}

inline EVAcceptedStreamSocket::socket_upgrade_to_enum EVAcceptedStreamSocket::getSockUpgradeTo()
{
	return _socket_upgraded_to;
}

inline void EVAcceptedStreamSocket::setSockUpgradeTo(socket_upgrade_to_enum to)
{
	_socket_upgraded_to = to;
}

inline int EVAcceptedStreamSocket::getSockMode()
{
	return _sock_mode;
}

inline void EVAcceptedStreamSocket::setSockMode(int mode)
{
	_sock_mode = mode;
}

inline int EVAcceptedStreamSocket::getCLRdFd()
{
	return _clRdFd;
}

inline int EVAcceptedStreamSocket::getCLWrFd()
{
	return _clWrFd;
}

inline void EVAcceptedStreamSocket::setStreamSocket(StreamSocket &ss)
{
	_streamSocket = ss;
}

inline void EVAcceptedStreamSocket::setWaitingTobeEnqueued(bool flg)
{
	_waiting_tobe_enqueued = flg;
}

inline bool EVAcceptedStreamSocket::waitingTobeEnqueued()
{
	return _waiting_tobe_enqueued;
}

inline bool EVAcceptedStreamSocket::srInSession(unsigned long sr_srl_num)
{
	//DEBUGPOINT("BASE SR SRL NUM = %ld\n", _base_sr_srl_num);
	//DEBUGPOINT("SR SRL NUM = %ld\n", sr_srl_num);
	return (sr_srl_num > _base_sr_srl_num);
}

inline void EVAcceptedStreamSocket::setBaseSRSrlNum(unsigned long sr_srl_num)
{
	_base_sr_srl_num = sr_srl_num;
}

inline bool EVAcceptedStreamSocket::getCLState()
{
	return _cl_state;
}

inline void EVAcceptedStreamSocket::setCLState(bool state)
{
	_cl_state = state;
}

inline EVAcceptedStreamSocket::accepted_sock_state EVAcceptedStreamSocket::getState()
{
	return _state;
}

inline void EVAcceptedStreamSocket::setState(EVAcceptedStreamSocket::accepted_sock_state state)
{
	_state = state;
}

inline void EVAcceptedStreamSocket::setSockInError()
{
	_socketInError = 1;
}

inline bool EVAcceptedStreamSocket::sockInError()
{
	return (_socketInError>0);
}

#if 0
inline void EVAcceptedStreamSocket::decrNumCSEvents()
{
	//_active_cs_events--;
	std::atomic_fetch_add(&_active_cs_events, -1);
}

inline void EVAcceptedStreamSocket::incrNumCSEvents()
{
	//_active_cs_events++;
	std::atomic_fetch_add(&_active_cs_events, 1);
}

inline bool EVAcceptedStreamSocket::pendingCSEvents()
{
	int cs_events = std::atomic_load(&_active_cs_events);
	//DEBUGPOINT("ACTIVE EVENTS = %d\n", _active_cs_events);
	return (cs_events>0);
}
#endif

inline void EVAcceptedStreamSocket::newresetNumCSEvents()
{
	std::atomic_store(&_new_active_cs_events, 0);
	return;
}

inline void EVAcceptedStreamSocket::newdecrNumCSEvents()
{
	//_new_active_cs_events--;
	std::atomic_fetch_add(&_new_active_cs_events, -1);
	int cs_events = std::atomic_load(&_new_active_cs_events);
	//DEBUGPOINT("ACTIVE EVENTS = %d for %d\n", cs_events, getSockfd());
}

inline void EVAcceptedStreamSocket::newincrNumCSEvents()
{
	//_new_active_cs_events++;
	std::atomic_fetch_add(&_new_active_cs_events, 1);
	int cs_events = std::atomic_load(&_new_active_cs_events);
	//DEBUGPOINT("ACTIVE EVENTS = %d for %d\n", cs_events, getSockfd());
}

inline bool EVAcceptedStreamSocket::newpendingCSEvents()
{
	int cs_events = std::atomic_load(&_new_active_cs_events);
	//DEBUGPOINT("ACTIVE EVENTS = %d for %d\n", cs_events, getSockfd());
	return (cs_events>0);
}

inline void EVAcceptedStreamSocket::setEventLoop(struct ev_loop* loop)
{
	_loop = loop;
}

inline struct ev_loop* EVAcceptedStreamSocket::getEventLoop()
{
	return _loop;
}

inline void EVAcceptedStreamSocket::setSocketWatcher(ev_io *socket_watcher_ptr)
{
	this->_socket_watcher = socket_watcher_ptr;
}

inline ev_io * EVAcceptedStreamSocket::getSocketWatcher()
{
	return this->_socket_watcher;
}

inline void EVAcceptedStreamSocket::setClientAddress(Net::SocketAddress addr)
{
	_clientAddress = addr;
}

inline void EVAcceptedStreamSocket::setServerAddress(Net::SocketAddress addr)
{
	_serverAddress = addr;
}

inline Net::SocketAddress& EVAcceptedStreamSocket::clientAddress()
{
	return _clientAddress;
}

inline Net::SocketAddress& EVAcceptedStreamSocket::serverAddress()
{
	return _serverAddress;
}

inline chunked_memory_stream * EVAcceptedStreamSocket::getResMemStream()
{
	return _res_memory_stream;
}

inline chunked_memory_stream * EVAcceptedStreamSocket::getReqMemStream()
{
	return _req_memory_stream;
}

inline ev_queue_type EVAcceptedStreamSocket::getIoEventQueue()
{
	return _event_queue;
}

} } // namespace evnet and Poco end.


#endif
