//
// EVUpstreamEventNotification.h
//
// Library: EVNet
// Package: EVTCPServer
// Module:  EVTCPServer
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <chunked_memory_stream.h>
#include "Poco/Net/Net.h"
#include "Poco/EVNet/EVNet.h"
#include "Poco/Net/StreamSocket.h"
#include "Poco/NotificationQueue.h"

#ifndef POCO_EVNET_EVUPSTREAMEVENTNOTIFICATION_INCLUDED
#define POCO_EVNET_EVUPSTREAMEVENTNOTIFICATION_INCLUDED

namespace Poco{ namespace EVNet {

class EVUpstreamEventNotification: public Notification
{
public:
	EVUpstreamEventNotification(long sr_num, int cb_evid_num);
	EVUpstreamEventNotification(long sr_num, poco_socket_t sockfd, int cb_evid_num, ssize_t ret, int err_no = 0);
	EVUpstreamEventNotification(long sr_num, poco_socket_t sockfd, int cb_evid_num, size_t ret, int err_no = 0);
	EVUpstreamEventNotification(long sr_num, poco_socket_t sockfd, int cb_evid_num, int ret, int err_no = 0);

	~EVUpstreamEventNotification();

	poco_socket_t sockfd();

	int getErrNo();
	void setErrNo(int err_no);

	ssize_t getRet();
	void setRet(ssize_t ret);

	int getCBEVIDNum();
	void setCBEVIDNum(int);

	void debug(const char* file, const int lineno);

	void setSRNum(long sr_num);

	long getSRNum();

	void setRecvStream(chunked_memory_stream *cms);
	chunked_memory_stream* getRecvStream();
	void setSendStream(chunked_memory_stream *cms);
	chunked_memory_stream* getSendStream();
	void setAddrInfo(struct addrinfo *a);
	struct addrinfo* getAddrInfo();

private:
	poco_socket_t			_sockfd;
	int						_errno;
	ssize_t					_ret;
	int						_cb_evid_num;
	long					_sr_num;
	chunked_memory_stream*	_send_stream;
	chunked_memory_stream*	_recv_stream;
	struct addrinfo*		_addr_info;
};

inline void EVUpstreamEventNotification::setAddrInfo(struct addrinfo *a)
{
	_addr_info = a;
}

inline struct addrinfo* EVUpstreamEventNotification::getAddrInfo()
{
	return _addr_info;
}

inline void EVUpstreamEventNotification::setRecvStream(chunked_memory_stream *cms)
{
	_recv_stream = cms;
}

inline chunked_memory_stream* EVUpstreamEventNotification::getRecvStream()
{
	return _recv_stream;
}

inline void EVUpstreamEventNotification::setSendStream(chunked_memory_stream *cms)
{
	_send_stream = cms;
}

inline chunked_memory_stream* EVUpstreamEventNotification::getSendStream()
{
	return _send_stream;
}

inline void EVUpstreamEventNotification::setSRNum(long sr_num)
{
	_sr_num = sr_num;
}

inline long EVUpstreamEventNotification::getSRNum()
{
	return _sr_num;
}

inline void EVUpstreamEventNotification::setErrNo(int err_no)
{
	_errno = err_no;
}

inline int EVUpstreamEventNotification::getErrNo()
{
	return _errno;
}

inline void EVUpstreamEventNotification::setRet(ssize_t ret)
{
	_ret = ret;;
}

inline ssize_t EVUpstreamEventNotification::getRet()
{
	return _ret;
}

inline void EVUpstreamEventNotification::setCBEVIDNum(int cb_evid_num)
{
	_cb_evid_num = cb_evid_num;
}

inline int EVUpstreamEventNotification::getCBEVIDNum()
{
	return _cb_evid_num;
}

inline void EVUpstreamEventNotification::debug(const char* file, const int lineno)
{
	printf("[%p][%s:%d] _sockfd = %d\n", pthread_self(), file, lineno, _sockfd);
	printf("[%p][%s:%d] _ret = %zd\n", pthread_self(), file, lineno, _ret);
	printf("[%p][%s:%d] _cb_evid_num = %d\n", pthread_self(), file, lineno, _cb_evid_num);
	printf("[%p][%s:%d] _errno = %d, %s\n", pthread_self(), file, lineno, _errno, strerror(_errno));
}

} } // namespace EVNet and Poco end.


#endif
