//
// EVEventNotification.h
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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <chunked_memory_stream.h>
#include "Poco/Net/Net.h"
#include "Poco/evnet/evnet.h"
#include "Poco/evnet/EVConnectedStreamSocket.h"
#include "Poco/Net/StreamSocket.h"
#include "Poco/NotificationQueue.h"

#ifndef POCO_EVNET_EVEVENTNOTIFICATION_INCLUDED
#define POCO_EVNET_EVEVENTNOTIFICATION_INCLUDED

namespace Poco{ namespace evnet {

class EVEventNotification: public Notification
{
public:
	typedef enum {
		NOT_READY = 0
		,READY_FOR_READ
		,READY_FOR_WRITE
		,READY_FOR_READWRITE
		,SOCKET_OPER_TIMED_OUT
	} sock_state;
	EVEventNotification(long sr_num, int cb_evid_num);
	EVEventNotification(long sr_num, poco_socket_t sockfd, int cb_evid_num, ssize_t ret, int err_no = 0);
	EVEventNotification(long sr_num, poco_socket_t sockfd, int cb_evid_num, size_t ret, int err_no = 0);
	EVEventNotification(long sr_num, poco_socket_t sockfd, int cb_evid_num, int ret, int err_no = 0);

	EVEventNotification();
	EVEventNotification(EVEventNotification & from);
	~EVEventNotification();

	poco_socket_t sockfd();

	int getErrNo();
	void setErrNo(int err_no);

	ssize_t getRet();
	void setRet(ssize_t ret);

	int getHRRet();
	void setHRRet(ssize_t ret);

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
	void setTaskReturnValue(void* a);
	void* getTaskReturnValue();
	void setFileFd(int fd);
	int getFileFd();
	void setFileOper(int oper);
	int getFileOper();
	long getRefSRNum();
	void setRefSRNum(long);
	sock_state getConnSockState();
	void setConnSockState(int);
	EVConnectedStreamSocket* getConnSock();
	void setConnSock(EVConnectedStreamSocket * s);

private:
	poco_socket_t				_sockfd;
	int							_errno;
	ssize_t						_ret;
	int							_hr_ret;
	int							_cb_evid_num;
	long						_sr_num;
	chunked_memory_stream*		_send_stream;
	chunked_memory_stream*		_recv_stream;
	struct addrinfo*			_addr_info;
	void*						_task_return_value;
	int							_file_fd;
	int							_oper;
	long						_ref_sr_num;
	sock_state					_conn_sock_state;
	EVConnectedStreamSocket		*_conn_sock;
};

inline EVConnectedStreamSocket* EVEventNotification::getConnSock()
{
	return _conn_sock;
}

inline void EVEventNotification::setConnSock(EVConnectedStreamSocket * s)
{
	_conn_sock = s;
}

inline EVEventNotification::sock_state EVEventNotification::getConnSockState()
{
	return _conn_sock_state;
}

inline void EVEventNotification::setConnSockState(int state)
{
	_conn_sock_state = (EVEventNotification::sock_state)state;
}


inline long EVEventNotification::getRefSRNum()
{
	return _ref_sr_num;
}

inline void EVEventNotification::setRefSRNum(long ref)
{
	_ref_sr_num = ref;
	return;
}

inline int EVEventNotification::getFileOper()
{
	return _oper;
}

inline void EVEventNotification::setFileOper(int oper)
{
	_oper = oper;
}

inline int EVEventNotification::getFileFd()
{
	return _file_fd;
}

inline void EVEventNotification::setFileFd(int fd)
{
	_file_fd = fd;
}

inline void EVEventNotification::setTaskReturnValue(void* a)
{
	_task_return_value = a;
}

inline void* EVEventNotification::getTaskReturnValue()
{
	return _task_return_value;
}

inline void EVEventNotification::setAddrInfo(struct addrinfo *a)
{
	_addr_info = a;
}

inline struct addrinfo* EVEventNotification::getAddrInfo()
{
	return _addr_info;
}

inline void EVEventNotification::setRecvStream(chunked_memory_stream *cms)
{
	_recv_stream = cms;
}

inline chunked_memory_stream* EVEventNotification::getRecvStream()
{
	return _recv_stream;
}

inline void EVEventNotification::setSendStream(chunked_memory_stream *cms)
{
	_send_stream = cms;
}

inline chunked_memory_stream* EVEventNotification::getSendStream()
{
	return _send_stream;
}

inline void EVEventNotification::setSRNum(long sr_num)
{
	_sr_num = sr_num;
}

inline long EVEventNotification::getSRNum()
{
	return _sr_num;
}

inline void EVEventNotification::setErrNo(int err_no)
{
	_errno = err_no;
}

inline int EVEventNotification::getErrNo()
{
	return _errno;
}

inline void EVEventNotification::setHRRet(ssize_t ret)
{
	_hr_ret = ret;;
}

inline int EVEventNotification::getHRRet()
{
	return _hr_ret;
}

inline void EVEventNotification::setRet(ssize_t ret)
{
	_ret = ret;;
}

inline ssize_t EVEventNotification::getRet()
{
	return _ret;
}

inline void EVEventNotification::setCBEVIDNum(int cb_evid_num)
{
	_cb_evid_num = cb_evid_num;
}

inline int EVEventNotification::getCBEVIDNum()
{
	return _cb_evid_num;
}

inline void EVEventNotification::debug(const char* file, const int lineno)
{
	printf("[%p][%s:%d] _sockfd = %d\n", (void*)pthread_self(), file, lineno, _sockfd);
	printf("[%p][%s:%d] _ret = %zd\n", (void*)pthread_self(), file, lineno, _ret);
	printf("[%p][%s:%d] _cb_evid_num = %d\n", (void*)pthread_self(), file, lineno, _cb_evid_num);
	printf("[%p][%s:%d] _errno = %d, %s\n", (void*)pthread_self(), file, lineno, _errno, strerror(_errno));
	printf("[%p][%s:%d] _task_return_value = %p\n", (void*)pthread_self(), file, lineno, _task_return_value);
}

} } // namespace evnet and Poco end.


#endif
