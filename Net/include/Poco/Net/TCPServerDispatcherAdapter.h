//
// TCPServerDispatcherAdapter.h
//
// Library: Net
// Package: TCPServer
// Module:  TCPServerDispatcherAdapter
//
// Definition of the TCPServerDispatcher class.
//
// Copyright (c) 2005-2006, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//
#include "Poco/Net/TCPServerConnection.h"

#ifndef Net_TCPServerDispatcherAdapter_INCLUDED
#define Net_TCPServerDispatcherAdapter_INCLUDED

namespace Poco {
namespace Net {

class Net_API TCPServerDispatcherAdapter 

{
public:
	TCPServerDispatcherAdapter();
	void tcpConnectionStart(TCPServerConnection *);
};

inline TCPServerDispatcherAdapter::TCPServerDispatcherAdapter() {}
inline void TCPServerDispatcherAdapter::tcpConnectionStart( TCPServerConnection * conn)
{
	return conn->start(true);
}
} } // namespace Poco::Net 
#endif
