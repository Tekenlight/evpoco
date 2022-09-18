//
// EVEventNotification.cpp
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

#include "Poco/evnet/EVEventNotification.h"

namespace Poco{ namespace evnet {

EVEventNotification::EVEventNotification(long sr_num, int cb_evid_num):
	_sr_num(sr_num),
	_cb_evid_num(cb_evid_num),
	_sockfd(-1),
	_ret(-1),
	_errno(0),
	_send_stream(0),
	_recv_stream(0),
	_addr_info(0),
	_task_return_value(0),
	_file_fd(-1),
	_oper(-1),
	_ref_sr_num(-1),
	_hr_ret(0),
	_conn_sock_state(EVEventNotification::NOT_READY),
	_conn_sock(0)
{
	//DEBUGPOINT("Here ret = [%zd]\n", _ret);
}

EVEventNotification::EVEventNotification(long sr_num, poco_socket_t sockfd, int cb_evid_num, ssize_t ret, int err_no):
	_sr_num(sr_num),
	_sockfd(sockfd),
	_cb_evid_num(cb_evid_num),
	_ret(ret),
	_errno(err_no),
	_send_stream(0),
	_recv_stream(0),
	_addr_info(0),
	_task_return_value(0),
	_file_fd(-1),
	_oper(-1),
	_ref_sr_num(-1),
	_hr_ret(0),
	_conn_sock_state(EVEventNotification::NOT_READY),
	_conn_sock(0)
{
	//DEBUGPOINT("Here ret = [%zd]\n", _ret);
}

EVEventNotification::EVEventNotification(long sr_num, poco_socket_t sockfd, int cb_evid_num, size_t ret, int err_no):
	_sr_num(sr_num),
	_sockfd(sockfd),
	_cb_evid_num(cb_evid_num),
	_ret(ret),
	_errno(err_no),
	_send_stream(0),
	_recv_stream(0),
	_addr_info(0),
	_task_return_value(0),
	_file_fd(-1),
	_oper(-1),
	_ref_sr_num(-1),
	_hr_ret(0),
	_conn_sock_state(EVEventNotification::NOT_READY),
	_conn_sock(0)
{
	//DEBUGPOINT("Here ret = [%zd]\n", _ret);
}

EVEventNotification::EVEventNotification():
	_sr_num(-1),
	_sockfd(-1),
	_cb_evid_num(-1),
	_ret(-1),
	_errno(-1),
	_send_stream(0),
	_recv_stream(0),
	_addr_info(0),
	_task_return_value(0),
	_file_fd(-1),
	_oper(-1),
	_ref_sr_num(-1),
	_hr_ret(0),
	_conn_sock_state(EVEventNotification::NOT_READY),
	_conn_sock(0)
{
	//DEBUGPOINT("Here ret = [%zd]\n", _ret);
}

EVEventNotification::EVEventNotification(long sr_num, poco_socket_t sockfd, int cb_evid_num, int ret, int err_no):
	_sr_num(sr_num),
	_sockfd(sockfd),
	_cb_evid_num(cb_evid_num),
	_ret(ret),
	_errno(err_no),
	_send_stream(0),
	_recv_stream(0),
	_addr_info(0),
	_task_return_value(0),
	_file_fd(-1),
	_oper(-1),
	_ref_sr_num(-1),
	_hr_ret(0),
	_conn_sock_state(EVEventNotification::NOT_READY),
	_conn_sock(0)
{
	//DEBUGPOINT("Here ret = [%zd]\n", _ret);
	//DEBUGPOINT("Here ret = [%zd]\n", ret);
}

EVEventNotification::EVEventNotification(EVEventNotification & from)
{
	this->_sr_num = from._sr_num;
	this->_sockfd = from._sockfd;
	this->_cb_evid_num = from._cb_evid_num;
	this->_ret = from._ret;
	this->_errno = from._errno;
	this->_send_stream = from._send_stream;
	this->_recv_stream = from._recv_stream;
	this->_addr_info = from._addr_info;
	this->_task_return_value = from._task_return_value;
	this->_file_fd = from._file_fd;
	this->_oper = from._oper;
	this->_ref_sr_num = from._ref_sr_num;
	this->_hr_ret = from._hr_ret;
	this->_conn_sock_state = from._conn_sock_state;
	this->_conn_sock = from._conn_sock;

	from._send_stream = NULL;
	from._recv_stream = NULL;
	from._addr_info = NULL;
	from._task_return_value = NULL;
}

EVEventNotification::~EVEventNotification()
{
	if (_addr_info) {
		freeaddrinfo(_addr_info);
		_addr_info = NULL;
	}
	if (_task_return_value) {
		free(_task_return_value);
		_task_return_value = NULL;
	}
}

poco_socket_t EVEventNotification::sockfd()
{
	return _sockfd;
}

} } // namespace evnet and Poco end.
