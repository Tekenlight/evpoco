//
// EVAcceptedSocket.h
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


#include "Poco/Net/Net.h"
#include "Poco/evnet/evnet.h"


#ifndef POCO_EVNET_EVACCEPTEDSOCKET_H_INCLUDED
#define POCO_EVNET_EVACCEPTEDSOCKET_H_INCLUDED

namespace Poco{ namespace evnet {


class Net_API EVAcceptedSocket
	/// This class is acts as the base class for
	/// Accepted sockets in EVTCPServer
	///
{
public:
	EVAcceptedSocket() {}
	~EVAcceptedSocket() {}
	virtual poco_socket_t getSockfd() = 0;
	virtual void newincrNumCSEvents() = 0;
};

} } // namespace evnet and Poco end.


#endif
