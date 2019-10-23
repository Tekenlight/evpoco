//
// EVUpstreamEventNotification.cpp
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

#include "Poco/EVNet/EVUpstreamEventNotification.h"

namespace Poco{ namespace EVNet {

EVUpstreamEventNotification::EVUpstreamEventNotification(long sr_num, poco_socket_t sockfd, what event, int cb_evid_num, ssize_t ret, int err_no):
	_sr_num(sr_num),
	_sockfd(sockfd),
	_event(event),
	_cb_evid_num(cb_evid_num),
	_ret(ret),
	_errno(err_no),
	_send_stream(0),
	_recv_stream(0)
{
}

EVUpstreamEventNotification::EVUpstreamEventNotification(long sr_num, poco_socket_t sockfd, what event, int cb_evid_num, size_t ret, int err_no):
	_sr_num(sr_num),
	_sockfd(sockfd),
	_event(event),
	_cb_evid_num(cb_evid_num),
	_ret(ret),
	_errno(err_no),
	_send_stream(0),
	_recv_stream(0)
{
}

EVUpstreamEventNotification::EVUpstreamEventNotification(long sr_num, poco_socket_t sockfd, what event, int cb_evid_num, int ret, int err_no):
	_sr_num(sr_num),
	_sockfd(sockfd),
	_event(event),
	_cb_evid_num(cb_evid_num),
	_ret(ret),
	_errno(err_no),
	_send_stream(0),
	_recv_stream(0)
{
}

EVUpstreamEventNotification::~EVUpstreamEventNotification()
{
}

poco_socket_t EVUpstreamEventNotification::sockfd()
{
	return _sockfd;
}

} } // namespace EVNet and Poco end.
