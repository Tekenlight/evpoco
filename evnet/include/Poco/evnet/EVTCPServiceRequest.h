//
// EVTCPServiceRequest.h
//
// Library: evnet
// Package: EVTCPServer
// Module:  EVTCPServer
//
// Tekenlight Solutions Pvt Ltd.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <thread_pool.h>

#include "Poco/Net/Net.h"
#include "Poco/Net/StreamSocket.h"
#include "Poco/NotificationQueue.h"
#include "Poco/evnet/EVConnectedStreamSocket.h"

using Poco::Net::StreamSocket;

#ifndef POCO_EVNET_EVTCPSERVICEREQUEST_INCLUDED
#define POCO_EVNET_EVTCPSERVICEREQUEST_INCLUDED

namespace Poco{ namespace evnet {

class EVTCPServiceRequest: public Notification
{
public:
	typedef enum {
		HOST_RESOLUTION
		,POLL_REQUEST
		,CONNECTION_REQUEST
		,SENDDATA_REQUEST
		,RECVDATA_REQUEST
		,FILEOPEN_NOTIFICATION
		,FILEREAD_NOTIFICATION
		,CLEANUP_REQUEST
		,GENERIC_TASK
		,GENERIC_TASK_NR
		,INITIATE_REDIS_CONNECTION
		,TRANSCEIVE_REDIS_COMMAND
		,CLOSE_REDIS_CONNECTION
		,RESERVE_ACC_SOCKET
		,SEND_DATA_ON_ACC_SOCK
		,TRACK_AS_WEBSOCKET
		,SET_EV_TIMER
		,SHUTDOWN_WEBSOCKET
		,WEBSOCKET_ACTIVE
		,RUN_LUA_SCRIPT
		,STOP_TRACKING_CONN_SOCK
	} what;
	typedef enum {
		NONE = 0
		,READ = 0x01
		,WRITE = 0x02
		,READWRITE = 0x01 | 0x02
	} poll_for;
	EVTCPServiceRequest(const EVTCPServiceRequest&);
	EVTCPServiceRequest& operator = (const EVTCPServiceRequest&);
	EVTCPServiceRequest(long sr_num, what event, poco_socket_t acc_fd, Net::StreamSocket& ss);
	EVTCPServiceRequest(long sr_num, int cb_evid_num, what event, poco_socket_t acc_fd, int file_fd);
	EVTCPServiceRequest(long sr_num, int cb_evid_num, what event, poco_socket_t acc_fd, Net::StreamSocket& ss);
	EVTCPServiceRequest(long sr_num, int cb_evid_num, what event, poco_socket_t acc_fd, Net::StreamSocket& ss, Net::SocketAddress& addr);
	EVTCPServiceRequest(long sr_num, int cb_evid_num, what event, poco_socket_t acc_fd, const char* domain_name, const char* serv_name);
	EVTCPServiceRequest(long sr_num, int cb_evid_num, what event, poco_socket_t acc_fd, task_func_with_return_t tf, void* td);
	EVTCPServiceRequest(long sr_num, int cb_evid_num, what event, poco_socket_t acc_fd, void * data);

	~EVTCPServiceRequest();

	poco_socket_t sockfd();

	poco_socket_t accSockfd();

	what getEvent();

	StreamSocket& getStreamSocket();

	Net::SocketAddress& getAddr();

	EVConnectedStreamSocket* getConnSock();
	void setConnSock(EVConnectedStreamSocket* cn);
	int getTimeOut();
	void setTimeOut(int time_out);
	int getCBEVIDNum();

	void setSRNum(long sr_num);

	long getSRNum();

	const char* getDomainName();

	struct addrinfo* getHints();

	const char* getServName();

	task_func_with_return_t getTaskFunc();

	void* getTaskInputData();

	int getFileFd();
	void setFileFd(int fd);
	void setPollFor(int);
	int getPollFor();
	int getConnSocketManaged();
	void setConnSocketManaged(int);
	int getPollForFd();
	void setPollForFd(int fd);

private:
	long						_sr_num;
	int							_cb_evid_num; // Unique Service request number, for identificaton
	what						_event; // One of connect, send data or recieve data
	poco_socket_t				_acc_fd; // fd of the accepted(listen) socket
	Net::StreamSocket*			_ssp; // Connected StreamSocket
	Net::SocketAddress			_addr; // Optional address needed only in the connect request
	const char*					_domain_name; // Either socket address or domain name can be passed
	const char*					_serv_name; // Either socket address or domain name can be passed
	task_func_with_return_t		_task_func;
	void*						_task_input_data; // Input data for generic task
	int							_file_fd; // File descriptor of the disk file
	int							_poll_for; // Whether EV_WRITE, EV_READ or both should be polled for in the _ssp
	int							_poll_for_fd; // Whether EV_WRITE, EV_READ or both should be polled for in the _ssp
	int							_conn_socket_managed;
	int							_time_out_for_oper;
	EVConnectedStreamSocket*	_cn;
};

inline poco_socket_t EVTCPServiceRequest::sockfd()
{
	return _ssp->impl()->sockfd();
}

inline poco_socket_t EVTCPServiceRequest::accSockfd()
{
	return _acc_fd;
}

inline StreamSocket& EVTCPServiceRequest::getStreamSocket()
{
	return *(_ssp);
}

inline Net::SocketAddress& EVTCPServiceRequest::getAddr()
{
	return _addr;
}

inline EVConnectedStreamSocket* EVTCPServiceRequest::getConnSock()
{
	return _cn;
}

inline void EVTCPServiceRequest::setConnSock(EVConnectedStreamSocket* cn)
{
	_cn = cn;
}

inline int EVTCPServiceRequest::getTimeOut()
{
	return _time_out_for_oper;
}

inline void EVTCPServiceRequest::setTimeOut(int time_out)
{
	_time_out_for_oper = time_out;
}

inline int EVTCPServiceRequest::getCBEVIDNum()
{
	return _cb_evid_num;
}

inline int EVTCPServiceRequest::getConnSocketManaged()
{
	return _conn_socket_managed;
}

inline void EVTCPServiceRequest::setConnSocketManaged(int c)
{
	_conn_socket_managed = c;
}

inline int EVTCPServiceRequest::getPollForFd()
{
	return _poll_for_fd;
}

inline void EVTCPServiceRequest::setPollForFd(int fd)
{
	_poll_for_fd = fd;
}

inline int EVTCPServiceRequest::getPollFor()
{
	return _poll_for;
}

inline void EVTCPServiceRequest::setPollFor(int poll_for)
{
	_poll_for = (EVTCPServiceRequest::poll_for)poll_for;
}

inline int EVTCPServiceRequest::getFileFd()
{
	return _file_fd;
}

inline void EVTCPServiceRequest::setFileFd(int fd)
{
	_file_fd = fd;
}

inline task_func_with_return_t EVTCPServiceRequest::getTaskFunc()
{
	return _task_func;
}

inline void* EVTCPServiceRequest::getTaskInputData()
{
	return _task_input_data;
}

inline EVTCPServiceRequest::what EVTCPServiceRequest::getEvent()
{
	return _event;
}

inline void EVTCPServiceRequest::setSRNum(long sr_num)
{
	_sr_num = sr_num;
}

inline long EVTCPServiceRequest::getSRNum()
{
	return _sr_num;
}

inline const char* EVTCPServiceRequest::getServName()
{
	return _serv_name;
}

inline const char* EVTCPServiceRequest::getDomainName()
{
	return _domain_name;
}

/*
inline struct addrinfo* EVTCPServiceRequest::getHints()
{
	return _hints;
}
*/

} } // namespace evnet and Poco end.


#endif
