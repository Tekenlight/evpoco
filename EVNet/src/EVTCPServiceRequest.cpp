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

#include "Poco/EVNet/EVTCPServiceRequest.h"

using Poco::Net::StreamSocket;

namespace Poco{ namespace EVNet {

EVTCPServiceRequest::EVTCPServiceRequest(int sr_num, what event, poco_socket_t acc_fd, Net::StreamSocket& ss):
	_sr_num(sr_num),
	_acc_fd(acc_fd),
	_event(event),
	_ss(ss)
{
}

EVTCPServiceRequest::EVTCPServiceRequest(int sr_num, what event, poco_socket_t acc_fd,
											Net::StreamSocket& ss, Net::SocketAddress& addr):
	_sr_num(sr_num),
	_acc_fd(acc_fd),
	_event(event),
	_ss(ss),
	_addr(addr)
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

int EVTCPServiceRequest::getSrNum()
{
	return _sr_num;
}

} } // namespace EVNet and Poco end.
