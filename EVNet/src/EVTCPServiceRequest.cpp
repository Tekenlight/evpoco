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


EVTCPServiceRequest::EVTCPServiceRequest(poco_socket_t sockfd, what event):
	_sockfd(sockfd),
	_event(event)
{
}


EVTCPServiceRequest::~EVTCPServiceRequest()
{
}


poco_socket_t EVTCPServiceRequest::sockfd()
{
	return _sockfd;
}

} } // namespace EVNet and Poco end.
