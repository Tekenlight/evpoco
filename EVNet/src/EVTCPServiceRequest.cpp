//
// EVTCPServiceRequest.cpp
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

#include "Poco/EVNet/EVNet.h"
#include "Poco/EVNet/EVTCPServiceRequest.h"

using Poco::Net::StreamSocket;

namespace Poco{ namespace EVNet {

EVTCPServiceRequest::EVTCPServiceRequest(long sr_num, what event, poco_socket_t acc_fd, Net::StreamSocket& ss):
	_sr_num(sr_num),
	_cb_evid_num(0),
	_acc_fd(acc_fd),
	_event(event),
	_ss(ss),
	_hints(0),
	_domain_name(0),
	_serv_name(0)
{
}

EVTCPServiceRequest::EVTCPServiceRequest(long sr_num, int cb_evid_num, what event, poco_socket_t acc_fd, Net::StreamSocket& ss):
	_sr_num(sr_num),
	_cb_evid_num(cb_evid_num),
	_acc_fd(acc_fd),
	_event(event),
	_ss(ss),
	_hints(0),
	_domain_name(0),
	_serv_name(0)
{
}

EVTCPServiceRequest::EVTCPServiceRequest(long sr_num, int cb_evid_num, what event, poco_socket_t acc_fd,
											Net::StreamSocket& ss, Net::SocketAddress& addr):
	_sr_num(sr_num),
	_cb_evid_num(cb_evid_num),
	_acc_fd(acc_fd),
	_event(event),
	_ss(ss),
	_addr(addr),
	_hints(0),
	_domain_name(0),
	_serv_name(0)
{
}

EVTCPServiceRequest::EVTCPServiceRequest(long sr_num, int cb_evid_num, what event, poco_socket_t acc_fd,
											 const char* domain_name, const char* serv_name):
	_sr_num(sr_num),
	_cb_evid_num(cb_evid_num),
	_acc_fd(acc_fd),
	_event(event),
	_domain_name(domain_name),
	_serv_name(serv_name),
	_hints(0)
{
}

EVTCPServiceRequest::~EVTCPServiceRequest()
{
}

poco_socket_t EVTCPServiceRequest::sockfd()
{
	return _ss.impl()->sockfd();
}

poco_socket_t EVTCPServiceRequest::accSockfd()
{
	return _acc_fd;
}

StreamSocket& EVTCPServiceRequest::getStreamSocket()
{
	return _ss;
}

Net::SocketAddress& EVTCPServiceRequest::getAddr()
{
	return _addr;
}

int EVTCPServiceRequest::getCBEVIDNum()
{
	return _cb_evid_num;
}

} } // namespace EVNet and Poco end.
