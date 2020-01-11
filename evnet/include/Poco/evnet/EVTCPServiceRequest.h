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
		,CONNECTION_REQUEST
		,SENDDATA_REQUEST
		,RECVDATA_REQUEST
		,CLEANUP_REQUEST
		,GENERIC_TASK
	} what;
	EVTCPServiceRequest(long sr_num, what event, poco_socket_t acc_fd, Net::StreamSocket& ss);
	EVTCPServiceRequest(long sr_num, int cb_event_num, what event, poco_socket_t acc_fd, Net::StreamSocket& ss);
	EVTCPServiceRequest(long sr_num, int cb_event_num, what event, poco_socket_t acc_fd, Net::StreamSocket& ss, Net::SocketAddress& addr);
	EVTCPServiceRequest(long sr_num, int cb_event_num, what event, poco_socket_t acc_fd, const char* domain_name, const char* serv_name);

	~EVTCPServiceRequest();

	poco_socket_t sockfd();

	poco_socket_t accSockfd();

	what getEvent();

	StreamSocket& getStreamSocket();

	Net::SocketAddress& getAddr();

	int getCBEVIDNum();

	void setSRNum(long sr_num);

	long getSRNum();

	inline const char* getDomainName();

	inline struct addrinfo* getHints();

	inline const char* getServName();

private:
	long					_sr_num;
	int						_cb_evid_num; // Unique Service request number, for identificaton
	what					_event; // One of connect, send data or recieve data
	poco_socket_t			_acc_fd; // fd of the accepted(listen) socket
	Net::StreamSocket		_ss; // Connected StreamSocket
	Net::SocketAddress		_addr; // Optional address needed only in the connect request
	//struct addrinfo*		_hints;
	const char*				_domain_name; // Either socket address or domain name can be passed
	const char*				_serv_name; // Either socket address or domain name can be passed
	task_func_type			_task_func;
	void*					_task_inout_data; // Input output data for generic task
};


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
