//
// EVTCPServiceRequest.h
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
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <thread_pool.h>

#include "Poco/Net/Net.h"
#include "Poco/Net/StreamSocket.h"
#include "Poco/NotificationQueue.h"

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
	} what;
	typedef enum {
		NONE = 0
		,READ = 0x01
		,WRITE = 0x02
		,READWRITE = 0x01 | 0x02
	} poll_for;
	EVTCPServiceRequest(long sr_num, what event, poco_socket_t acc_fd, Net::StreamSocket& ss);
	EVTCPServiceRequest(long sr_num, int cb_evid_num, what event, poco_socket_t acc_fd, int file_fd);
	EVTCPServiceRequest(long sr_num, int cb_evid_num, what event, poco_socket_t acc_fd, Net::StreamSocket& ss);
	EVTCPServiceRequest(long sr_num, int cb_evid_num, what event, poco_socket_t acc_fd, Net::StreamSocket& ss, Net::SocketAddress& addr);
	EVTCPServiceRequest(long sr_num, int cb_evid_num, what event, poco_socket_t acc_fd, const char* domain_name, const char* serv_name);
	EVTCPServiceRequest(long sr_num, int cb_evid_num, what event, poco_socket_t acc_fd, task_func_with_return_t tf, void* td);

	~EVTCPServiceRequest();

	poco_socket_t sockfd();

	poco_socket_t accSockfd();

	what getEvent();

	StreamSocket& getStreamSocket();

	Net::SocketAddress& getAddr();

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

private:
	long						_sr_num;
	int							_cb_evid_num; // Unique Service request number, for identificaton
	what						_event; // One of connect, send data or recieve data
	poco_socket_t				_acc_fd; // fd of the accepted(listen) socket
	Net::StreamSocket			_ss; // Connected StreamSocket
	Net::SocketAddress			_addr; // Optional address needed only in the connect request
	const char*					_domain_name; // Either socket address or domain name can be passed
	const char*					_serv_name; // Either socket address or domain name can be passed
	task_func_with_return_t		_task_func;
	void*						_task_input_data; // Input data for generic task
	int							_file_fd; // File descriptor of the disk file
	int							_poll_for; // Whether EV_WRITE, EV_READ or both should be polled for in the _ss
};

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
