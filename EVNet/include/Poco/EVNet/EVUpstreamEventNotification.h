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

#include <errno.h>
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
	typedef enum {
		SOCKET_CONNECTED=0
		,DATA_RECEIVED
		,DATA_SENT
		,ERROR
	} what;
	EVUpstreamEventNotification(long sr_num, poco_socket_t sockfd, what event, int cb_evid_num, ssize_t bytes, int err_no = 0);
	EVUpstreamEventNotification(long sr_num, poco_socket_t sockfd, what event, int cb_evid_num, size_t bytes, int err_no = 0);
	EVUpstreamEventNotification(long sr_num, poco_socket_t sockfd, what event, int cb_evid_num, int bytes, int err_no = 0);

	~EVUpstreamEventNotification();

	poco_socket_t sockfd();

	what getEvent();
	
	int getErrNo();

	ssize_t getBytes();

	int getCBEVIDNum();
	void setCBEVIDNum(int);

	void debug(const char* file, const int lineno);

	void setSRNum(long sr_num);

	long getSRNum();

	void setRecvStream(chunked_memory_stream *cms);
	chunked_memory_stream* getRecvStream();
	void setSendStream(chunked_memory_stream *cms);
	chunked_memory_stream* getSendStream();

private:
	poco_socket_t			_sockfd;
	what					_event;
	int						_errno;
	ssize_t					_bytes;
	int						_cb_evid_num;
	long					_sr_num;
	chunked_memory_stream*	_send_stream;
	chunked_memory_stream*	_recv_stream;
};

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

inline EVUpstreamEventNotification::what EVUpstreamEventNotification::getEvent()
{
	return _event;
}

inline int EVUpstreamEventNotification::getErrNo()
{
	return _errno;
}

inline ssize_t EVUpstreamEventNotification::getBytes()
{
	return _bytes;
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
	printf("[%p][%s:%d] _event = %d\n", pthread_self(), file, lineno, _event);
	printf("[%p][%s:%d] _bytes = %zd\n", pthread_self(), file, lineno, _bytes);
	printf("[%p][%s:%d] _cb_evid_num = %d\n", pthread_self(), file, lineno, _cb_evid_num);
	printf("[%p][%s:%d] _errno = %d\n", pthread_self(), file, lineno, _errno);
}

} } // namespace EVNet and Poco end.


#endif
